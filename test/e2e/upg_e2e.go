// upg_e2e.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2021 Travelping GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exttest

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.fd.io/govpp.git/api"
	"github.com/google/gopacket/layers"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/pkg/errors"
	gtpuie "github.com/wmnsk/go-gtp/gtpv1/ie"
	gtpumessage "github.com/wmnsk/go-gtp/gtpv1/message"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/travelping/upg-vpp/test/e2e/binapi/fib_types"
	"github.com/travelping/upg-vpp/test/e2e/binapi/ip_types"
	"github.com/travelping/upg-vpp/test/e2e/binapi/upf"
	"github.com/travelping/upg-vpp/test/e2e/framework"
	"github.com/travelping/upg-vpp/test/e2e/network"
	"github.com/travelping/upg-vpp/test/e2e/pfcp"
	"github.com/travelping/upg-vpp/test/e2e/traffic"
	"github.com/travelping/upg-vpp/test/e2e/util"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

const (
	NON_APP_TRAFFIC_THRESHOLD = 1000
	IPFIX_PORT                = 4739
)

var _ = ginkgo.Describe("TDF", func() {
	describeMode("IPv4", framework.UPGModeTDF, framework.UPGIPModeV4)
	describeMode("IPv6", framework.UPGModeTDF, framework.UPGIPModeV6)
})

var _ = ginkgo.Describe("PGW", func() {
	describeMode("IPv4", framework.UPGModePGW, framework.UPGIPModeV4)
	describeMode("IPv6", framework.UPGModePGW, framework.UPGIPModeV6)
	ginkgo.Context("[GTP-U extensions]", func() {
		var seid pfcp.SEID
		corruptTPDU := false
		n := 0

		f := framework.NewDefaultFramework(framework.UPGModePGW, framework.UPGIPModeV4)
		f.TPDUHook = func(tpdu *gtpumessage.TPDU, fromPGW bool) {
			defer ginkgo.GinkgoRecover()
			if fromPGW {
				// ext flag must be reset
				framework.ExpectEqual((tpdu.Header.Flags>>2)&1, uint8(0))
				return
			}

			// Add an extension to T-PDU
			// GTP library doesn't support extensions, so some hacks are needed
			// TODO: fix the library
			var prepend []byte
			if corruptTPDU {
				n++
				if n%13 != 0 {
					// don't corrupt each datagram
					return
				}
				prepend = []byte{
					// TODO: try zeros
					0x7e, // seq number hi (unused)
					0xf0, // seq number lo (unused)
					0x38, // N-PDU number (unused)
					0xf7, // next extension type
					0,    // ext header length (broken! must not be 0)
				}
			} else {
				prepend = []byte{
					0,    // seq number hi (unused)
					0,    // seq number lo (unused)
					0,    // N-PDU number (unused)
					0x32, // next extension type
					1,    // ext header length
					0,    // ext content
					0xff, // ext content
					0,    // next ext type: no extension
				}
			}
			tpdu.Header.Flags |= 4
			tpdu.Payload = append(prepend, tpdu.Payload...)
		}

		ginkgo.BeforeEach(func() {
			seid = startMeasurementSession(f, &framework.SessionConfig{AppName: framework.HTTPAppName})
			n = 0
			corruptTPDU = false
		})

		ginkgo.It("should correctly handle the extensions", func() {
			verifyConnFlood(f, false)
			deleteSession(f, seid, true)
		})

		ginkgo.Context("[corrupt GTP-U]", func() {
			ginkgo.BeforeEach(func() {
				corruptTPDU = true
			})

			ginkgo.It("should not hang on corrupt GTP-U datagrams", func() {
				verifyConnFlood(f, false)
				deleteSession(f, seid, true)
			})
		})
	})
})

func describeMode(title string, mode framework.UPGMode, ipMode framework.UPGIPMode) {
	ginkgo.Describe(title, func() {
		f := framework.NewDefaultFramework(mode, ipMode)
		describeMeasurement(f)
		describePDRReplacement(f)
		describeRoutingPolicy(f)
		// TODO: fix these test cases for IPv6
		if ipMode == framework.UPGIPModeV4 {
			describeMTU(mode, ipMode)
			if mode == framework.UPGModeTDF {
				describeNAT(f)
			}
		}
	})
	describeIPFIX(title, mode, ipMode)
}

func describeMeasurement(f *framework.Framework) {
	ginkgo.Describe("session measurement", func() {
		var ms *pfcp.PFCPMeasurement
		var seid pfcp.SEID
		var flowStr string

		sessionContext := func(desc string, cfg framework.SessionConfig, body func()) {
			ginkgo.Context(desc, func() {
				ginkgo.BeforeEach(func() {
					seid = startMeasurementSession(f, &cfg)
				})

				body()
			})
		}

		verify := func(cfg traffic.TrafficConfig) {
			var err error
			runTrafficGen(f, cfg, &traffic.PreciseTrafficRec{})
			flowStr, err = f.VPP.Ctl("show upf flows")
			framework.ExpectNoError(err, "show upf flows")
			ms = deleteSession(f, seid, true)
		}

		sessionContext("[no proxy]", framework.SessionConfig{}, func() {
			ginkgo.It("counts plain HTTP traffic", func() {
				verify(smallVolumeHTTPConfig(nil))
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})

			ginkgo.It("counts UDP traffic", func() {
				verify(&traffic.UDPPingConfig{})
				verifyNonAppMeasurement(f, ms, layers.IPProtocolUDP, nil)
			})

			ginkgo.It("counts ICMP echo requests and responses", func() {
				verify(&traffic.ICMPPingConfig{})
				proto := layers.IPProtocolICMPv4
				if f.IPMode == framework.UPGIPModeV6 {
					proto = layers.IPProtocolICMPv6
				}
				verifyNonAppMeasurement(f, ms, proto, nil)
			})
		})

		ginkgo.Context("[ip rules]", func() {
			var appServerIP net.IP
			ginkgo.BeforeEach(func() {
				appServerIP = f.AddServerIP()
				f.VPP.Ctl(
					"upf application IPAPP rule 3000 add ipfilter permit out ip from %s to assigned",
					appServerIP,
				)
				// TODO: use VPP-side ping in the framework, too
				f.VPP.Ctl("ping %s source sgi0 repeat 3", appServerIP)

				seid = startMeasurementSession(f, &framework.SessionConfig{
					AppName: framework.IPAppName,
				})
			})

			ginkgo.It("counts plain HTTP traffic for app detection hit", func() {
				trafficCfg := smallVolumeHTTPConfig(nil)
				trafficCfg.AddServerIP(appServerIP)
				verify(trafficCfg)
				verifyAppMeasurement(f, ms, layers.IPProtocolTCP, appServerIP)
			})

			ginkgo.It("counts UDP traffic for app detection hit", func() {
				trafficCfg := &traffic.UDPPingConfig{}
				trafficCfg.AddServerIP(appServerIP)
				verify(trafficCfg)
				verifyAppMeasurement(f, ms, layers.IPProtocolUDP, appServerIP)
			})

			ginkgo.It("counts plain HTTP traffic (no app hit)", func() {
				verify(smallVolumeHTTPConfig(nil))
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})
		})

		sessionContext("[proxy]", framework.SessionConfig{AppName: framework.HTTPAppName}, func() {
			ginkgo.It("counts plain HTTP traffic (no app hit)", func() {
				verify(smallVolumeHTTPConfig(nil))
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})

			ginkgo.It("counts traffic for app detection hit on plain HTTP", func() {
				verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
					UseFakeHostname: true,
				}))
				verifyAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})

			ginkgo.It("can handle a big number of HTTP connections at once", func() {
				verifyConnFlood(f, false)
				// we only verify proxy cleanup for "clean" (non-netem)
				// multi-connection test b/c the flows there should time out
				// rather quickly.
				// TODO: also verify for netem, but only in non-quick mode
				countFlows := func() int {
					f.Ping("ue", f.ServerIP(), 1)
					r, err := f.VPP.Ctl("show upf flows")
					framework.ExpectNoError(err)
					lines := strings.Split(r, "\n")
					n := 0
					for _, l := range lines {
						if strings.TrimSpace(l) != "" {
							n++
						}
					}
					return n
				}
				// just one flow must remain, corresponding to the ping
				gomega.Eventually(countFlows, 6*time.Minute, 10*time.Second).Should(gomega.Equal(1))
				// all of the proxy sessions must be cleaned up together with the flows
				proxySessionStr, err := f.VPP.Ctl("show upf proxy session")
				framework.ExpectNoError(err)
				framework.ExpectEqual(strings.TrimSpace(proxySessionStr), "")

				deleteSession(f, seid, true)
			})

			ginkgo.It("can handle a big number of HTTP connections at once [netem]", func() {
				verifyConnFlood(f, true)
				deleteSession(f, seid, true)
			})

			ginkgo.It("can survive session creation-deletion loop", func() {
				verifySessionDeletionLoop(f, &seid)
			})
		})

		ginkgo.Context("[proxy bypass]", func() {
			var bypassTrafficCfg traffic.HTTPConfig

			describeProxyBypass := func(skipIPv6 bool) {
				ginkgo.It("should not proxy traffic when higher precedence PDRs have no app id", func() {
					// FIXME: there's an IPv6-related problem with extra server IPs that is not caused
					// by the proxy bypass, as it also happens if proxy bypass PDRs are removed together
					// with app id. For now, let's only test IPv6 mode with port-based SDF Filters.
					if skipIPv6 && f.IPMode == framework.UPGIPModeV6 {
						ginkgo.Skip("FIXME: skipping IPv6 version of the test")
					}
					verify(&bypassTrafficCfg)
					// the flow should not be proxied
					gomega.Expect(flowStr).To(gomega.ContainSubstring("proxy 0"))
					gomega.Expect(flowStr).NotTo(gomega.ContainSubstring("proxy 1"))
				})

				ginkgo.It("should not prevent ADF from working (no app hit)", func() {
					verify(smallVolumeHTTPConfig(nil))
					verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)

					// the flow should be proxied
					gomega.Expect(flowStr).NotTo(gomega.ContainSubstring("proxy 0"))
					gomega.Expect(flowStr).To(gomega.ContainSubstring("proxy 1"))
				})

				ginkgo.It("should not prevent ADF from working (app hit)", func() {
					verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
						UseFakeHostname: true,
					}))
					verifyAppMeasurement(f, ms, layers.IPProtocolTCP, nil)

					// the flow should be proxied
					gomega.Expect(flowStr).NotTo(gomega.ContainSubstring("proxy 0"))
					gomega.Expect(flowStr).To(gomega.ContainSubstring("proxy 1"))
				})
			}

			ginkgo.Context("[port based]", func() {
				ginkgo.BeforeEach(func() {
					bypassTrafficCfg = traffic.HTTPConfig{
						ClientPort: 8883,
						ServerPort: 8883,
					}
					sessionCfg := framework.SessionConfig{
						AppName:        framework.HTTPAppName,
						NoADFSDFFilter: "permit out ip from any 8883 to assigned",
					}
					seid = startMeasurementSession(f, &sessionCfg)
				})

				describeProxyBypass(false)
			})

			ginkgo.Context("[ip based]", func() {
				ginkgo.BeforeEach(func() {
					bypassServerIP := f.AddServerIP()
					bypassTrafficCfg = traffic.HTTPConfig{
						ServerIPs: []net.IP{bypassServerIP},
					}
					sessionCfg := framework.SessionConfig{
						AppName: framework.HTTPAppName,
						NoADFSDFFilter: fmt.Sprintf(
							"permit out ip from %s to assigned",
							bypassServerIP),
					}
					seid = startMeasurementSession(f, &sessionCfg)
				})

				describeProxyBypass(true)
			})
		})

		sessionContext("[redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("counts UPG's HTTP redirects", func() {
				verify(&traffic.RedirectConfig{
					RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
					RedirectResponseSubstr: "<title>Redirection</title>",
				})
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})
		})
	})
}

func describePDRReplacement(f *framework.Framework) {
	ginkgo.Describe("PDR replacement", func() {
		var ms *pfcp.PFCPMeasurement
		var seid pfcp.SEID
		var sessionCfg framework.SessionConfig

		sessionContext := func(desc string, cfg framework.SessionConfig, body func()) {
			ginkgo.Context(desc, func() {
				ginkgo.BeforeEach(func() {
					sessionCfg = cfg
					seid = startMeasurementSession(f, &sessionCfg)
				})

				body()
			})
		}

		pdrReplacementLoop := func(toggleAppPDR bool, tgDone chan error) {
		LOOP:
			for {
				select {
				case <-tgDone:
					break LOOP
				case <-time.After(1 * time.Second):
				}
				ies := sessionCfg.DeletePDRs()
				// changing the PDR IDs crashes UPG as of 1.0.1
				// while it's handling a packet belonging to an affected flow
				sessionCfg.IdBase ^= 8
				if toggleAppPDR {
					if sessionCfg.AppName == "" {
						sessionCfg.AppName = framework.HTTPAppName
					} else {
						sessionCfg.AppName = ""
					}
				}
				ies = append(ies, sessionCfg.CreatePDRs()...)
				_, err := f.PFCP.ModifySession(f.VPP.Context(context.Background()), seid, ies...)
				framework.ExpectNoError(err)
			}
		}

		verify := func(cfg traffic.TrafficConfig, rec traffic.TrafficRec, toggleAppPDR bool) {
			tgDone := startTrafficGen(f, cfg, rec)
			pdrReplacementLoop(toggleAppPDR, tgDone)
			ms = deleteSession(f, seid, true)
			framework.ExpectNoError(rec.Verify())
		}

		sessionContext("[no proxy]", framework.SessionConfig{}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting", func() {
				verify(smallVolumeHTTPConfig(nil), &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})

			ginkgo.It("doesn't affect UDP traffic accounting", func() {
				verify(&traffic.UDPPingConfig{}, &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolUDP, nil)
			})
		})

		sessionContext("[proxy]", framework.SessionConfig{AppName: framework.HTTPAppName}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting (no app hit)", func() {
				verify(smallVolumeHTTPConfig(nil), &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})

			ginkgo.It("doesn't affect traffic accounting with app detection hit on plain HTTP", func() {
				verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
					UseFakeHostname: true,
				}), &traffic.PreciseTrafficRec{}, false)
				verifyAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})
		})

		sessionContext("[redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("doesn't affect traffic accounting for UPG's HTTP redirects", func() {
				verify(&traffic.RedirectConfig{
					RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
					RedirectResponseSubstr: "<title>Redirection</title>",
				}, &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})
		})

		sessionContext("[proxy on-off]", framework.SessionConfig{AppName: framework.HTTPAppName}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting (no app hit)", func() {
				verify(smallVolumeHTTPConfig(nil), &traffic.PreciseTrafficRec{}, true)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)
			})

			ginkgo.It("doesn't disrupt traffic with app detection hit on plain HTTP", func() {
				// accounting is obviously disturbed in this case
				// (could be still verified, but harder to do so)
				verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
					UseFakeHostname: true,
				}), &traffic.PreciseTrafficRec{}, true)
			})
		})

		sessionContext("[proxy on-off+redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("doesn't disrupt UPG's HTTP redirects", func() {
				verify(&traffic.RedirectConfig{
					RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
					RedirectResponseSubstr: "<title>Redirection</title>",
					// XXX: should work initially, too.
					// May happen to fail due to delays during parallel test runs, though
					Retry: true,
				}, &traffic.PreciseTrafficRec{}, true)
			})
		})

		sessionContext("[proxy off-on]", framework.SessionConfig{AppName: framework.HTTPAppName}, func() {
			ginkgo.It("doesn't permanently disrupt plain HTTP traffic (no app hit)", func() {
				// FIXME: could also avoid disruptions altogethern
				// and also breaking traffic accounting,
				// but actually it may lose some connections
				// and the accounting may be off by a packet or so, e.g.:
				// bad uplink volume: reported 83492, actual 83440
				verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
					Retry: true,
				}), &traffic.PreciseTrafficRec{}, true)
			})

			ginkgo.It("doesn't permanently disrupt traffic with app detection hit on plain HTTP", func() {
				// accounting is obviously disturbed in this case
				// (could be still verified, but harder to do so)
				verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
					Retry:           true,
					UseFakeHostname: true,
				}), &traffic.PreciseTrafficRec{}, true)
			})
		})

		sessionContext("[proxy off-on+redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("doesn't permanently disrupt UPG's HTTP redirects", func() {
				verify(&traffic.RedirectConfig{
					RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
					RedirectResponseSubstr: "<title>Redirection</title>",
					Retry:                  true,
				}, &traffic.PreciseTrafficRec{}, true)
			})
		})
	})
}

var _ = ginkgo.Describe("CLI debug commands", func() {
	f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
	ginkgo.Context("show upf session", func() {
		var ueIPs []net.IP
		var seids []pfcp.SEID
		var seidsHex []string

		ginkgo.BeforeEach(func() {
			var errs []error
			var specs []pfcp.SessionOpSpec
			ueIPs = []net.IP{f.UEIP(), f.AddUEIP()}
			for _, ueIP := range ueIPs {
				specs = append(specs, pfcp.SessionOpSpec{
					IEs: framework.SessionConfig{
						IdBase: 1,
						UEIP:   ueIP,
						Mode:   f.Mode,
					}.SessionIEs(),
				})
			}
			seids, errs = f.PFCP.EstablishSessions(f.Context, specs)
			for _, err := range errs {
				framework.ExpectNoError(err)
			}
			seidsHex = nil
			for _, seid := range seids {
				seidsHex = append(seidsHex, fmt.Sprintf("0x%016x", seid))
			}
		})

		ginkgo.AfterEach(func() {
			ginkgo.By("deleting the PFCP sessions")
			deleteSessions(f, seids, false)
		})

		verifyShowUPFSession := func(haveSeid0 bool, haveSeid1 bool, cmd string, args ...interface{}) {
			out, err := f.VPP.Ctl(cmd, args...)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "show upf session")
			if haveSeid0 {
				gomega.Expect(out).To(gomega.ContainSubstring(seidsHex[0]))
			} else {
				gomega.Expect(out).NotTo(gomega.ContainSubstring(seidsHex[0]))
			}
			if haveSeid1 {
				gomega.Expect(out).To(gomega.ContainSubstring(seidsHex[1]))
			} else {
				gomega.Expect(out).NotTo(gomega.ContainSubstring(seidsHex[1]))
			}
		}

		verifyShowUPFSessionCount := func(expectedCount int, cmd string, args ...interface{}) {
			out, err := f.VPP.Ctl(cmd, args...)
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "show upf session")
			n := 0
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, "CP F-SEID:") {
					n++
				}
			}
			framework.ExpectEqual(n, expectedCount, "session count")
		}

		ginkgo.It("can be filtered by UP SEID", func() {
			verifyShowUPFSession(true, true, "show upf session")
			verifyShowUPFSession(true, false, "show upf session up seid %s", seidsHex[0])
			verifyShowUPFSession(true, false, "show upf session up seid %d", seids[0])
			verifyShowUPFSession(false, true, "show upf session up seid %s", seidsHex[1])
			verifyShowUPFSession(false, true, "show upf session up seid %d", seids[1])
		})

		ginkgo.It("honors 'limit' value", func() {
			verifyShowUPFSessionCount(1, "show upf session limit 1")
			// "limit 0" stands for "unlimited"
			verifyShowUPFSessionCount(2, "show upf session limit 0")
		})

		ginkgo.It("shows flows belonging to the session", func() {
			runTrafficGen(f, &traffic.UDPPingConfig{}, &traffic.SimpleTrafficRec{})
			out, err := f.VPP.Ctl("show upf session up seid %s flows", seidsHex[0])
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "show upf session")
			gomega.Expect(out).To(gomega.ContainSubstring(ueIPs[0].String()))
			gomega.Expect(out).NotTo(gomega.ContainSubstring(ueIPs[1].String()))
			out, err = f.VPP.Ctl("show upf session up seid %s flows", seidsHex[1])
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "show upf session")
			gomega.Expect(strings.TrimSpace(out)).To(gomega.BeEmpty())
		})
	})
})

// TODO: validate both binapi and CLI against each other
var _ = ginkgo.Describe("UPG Binary API", func() {
	ginkgo.Context("for upf nat pool", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)

		addPool := func(start string, end string, nwi string, name string, isAdd bool, check bool) error {
			startIp, _ := ip_types.ParseIP4Address(start)
			endIp, _ := ip_types.ParseIP4Address(end)

			nameBytes := []byte(name)

			req := &upf.UpfNatPoolAdd{
				IsAdd: isAdd,

				MinPort:   2000,
				MaxPort:   3000,
				BlockSize: 1,
				Start:     startIp,
				End:       endIp,

				NameLen: uint8(len(nameBytes)),
				Name:    nameBytes,
				Nwi:     util.EncodeFQDN(nwi),
			}
			reply := &upf.UpfNatPoolAddReply{}
			err := f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply)

			if check {
				gomega.Expect(err).To(gomega.Succeed(), "upf_nat_pool_add")
			}
			return err
		}

		type poolPairing struct {
			nwi          string
			name         string
			blockSize    uint16
			maxUsers     uint32
			currentUsers uint32
		}

		dumpPools := func() []poolPairing {
			reqCtx := f.VPP.ApiChannel.SendMultiRequest(&upf.UpfNatPoolDump{})
			var ret []poolPairing
			for {
				msg := &upf.UpfNatPoolDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).To(gomega.BeNil())
				if stop {
					break
				}

				nwi := strings.TrimRight(string(msg.Nwi), "\x00")
				name := strings.TrimRight(string(msg.Name), "\x00")

				ret = append(ret, poolPairing{
					nwi:          util.DecodeFQDN([]byte(nwi)),
					name:         name,
					blockSize:    msg.BlockSize,
					maxUsers:     msg.MaxUsers,
					currentUsers: msg.CurrentUsers,
				})
			}

			return ret
		}

		ginkgo.It("adds a nat pool", func() {
			gomega.Expect(dumpPools()).To(gomega.BeEmpty())
			addPool("10.0.0.2", "10.0.0.3", "sgi", "mypool", true, true)
			gomega.Expect(dumpPools()).To(gomega.ConsistOf(
				poolPairing{"sgi", "mypool", 1, 2000, 0},
			))
			addPool("10.0.0.4", "10.0.0.5", "sgi", "mypool2", true, true)
			gomega.Expect(dumpPools()).To(gomega.ConsistOf(
				poolPairing{"sgi", "mypool", 1, 2000, 0},
				poolPairing{"sgi", "mypool2", 1, 2000, 0},
			))
		})

		ginkgo.It("removes a nat pool", func() {
			addPool("10.0.0.2", "10.0.0.3", "sgi", "mypool", true, true)
			gomega.Expect(dumpPools()).To(gomega.ConsistOf(
				poolPairing{"sgi", "mypool", 1, 2000, 0},
			))
			addPool("10.0.0.2", "10.0.0.3", "sgi", "mypool", false, true)
			gomega.Expect(dumpPools()).To(gomega.BeEmpty())
		})

		ginkgo.It("tries to add a nat pool with too long name", func() {
			addPool("10.0.0.2", "10.0.0.3", "sgi", strings.Repeat("a", 64), true, true)

			err := addPool("10.0.0.2", "10.0.0.3", "sgi", strings.Repeat("a", 65), true, false)
			gomega.Expect(err).To(gomega.Equal(api.VPPApiError(api.INVALID_VALUE)))

			// 63 + leading label should pass
			addPool("10.0.0.2", "10.0.0.3", strings.Repeat("a", 63), "sgi", true, true)

			// should fail
			err = addPool("10.0.0.2", "10.0.0.3", strings.Repeat("a", 64), "sgi", true, false)
			gomega.Expect(err).To(gomega.Equal(api.VPPApiError(api.INVALID_VALUE)))
		})
	})

	ginkgo.Context("for upf ueip pool", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)

		addPool := func(isAdd bool, identity string, nwi_name string, check bool) error {
			identityConverted := []byte(identity)
			nwiConverted := util.EncodeFQDN(nwi_name)
			req := &upf.UpfUeipPoolNwiAdd{
				IsAdd:       isAdd,
				Identity:    identityConverted,
				IdentityLen: uint8(len(identityConverted)),
				NwiName:     nwiConverted,
			}
			reply := &upf.UpfUeipPoolNwiAddReply{}

			err := f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply)
			if check {
				gomega.Expect(err).To(gomega.Succeed(), "upf_tdf_ul_enable_disable")
			}
			return err
		}

		type poolPairing struct {
			identity string
			nwi      string
		}

		dumpPools := func() []poolPairing {
			reqCtx := f.VPP.ApiChannel.SendMultiRequest(&upf.UpfUeipPoolDump{})
			var ret []poolPairing
			for {
				msg := &upf.UpfUeipPoolDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).To(gomega.BeNil())
				if stop {
					break
				}

				identity := strings.TrimRight(string(msg.Identity), "\x00")
				nwiName := strings.TrimRight(string(msg.NwiName), "\x00")

				ret = append(ret, poolPairing{
					identity: identity,
					nwi:      util.DecodeFQDN([]byte(nwiName)),
				})
			}

			return ret
		}

		ginkgo.It("adds and removes a pool", func() {
			addPool(true, "sgi", "mypool", true)
			addPool(true, "test", "mypool", true)

			gomega.Expect(dumpPools()).To(gomega.ConsistOf(
				poolPairing{"sgi", "mypool"}, poolPairing{"test", "mypool"},
			))

			addPool(false, "test", "mypool", true)

			gomega.Expect(dumpPools()).To(gomega.ConsistOf(
				poolPairing{"sgi", "mypool"},
			))
		})

		ginkgo.It("tries to add a pool with too long name", func() {
			addPool(true, strings.Repeat("a", 64), "sgi", true)

			err := addPool(true, strings.Repeat("a", 65), "sgi", false)
			gomega.Expect(err).To(gomega.Equal(api.VPPApiError(api.INVALID_VALUE)))

			// 63 + leading label should pass
			addPool(true, "sgi", strings.Repeat("a", 63), true)

			// should fail
			err = addPool(true, "sgi", strings.Repeat("a", 64), false)
			gomega.Expect(err).To(gomega.Equal(api.VPPApiError(api.INVALID_VALUE)))
		})
	})

	ginkgo.Context("for upf tdf ul enable", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)

		ginkgo.It("enables the interface", func() {
			req := &upf.UpfTdfUlEnableDisable{
				Enable:    true,
				Interface: 0,
				IsIPv6:    false,
			}
			reply := &upf.UpfTdfUlEnableDisableReply{}

			gomega.Expect(
				f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply),
			).To(gomega.Succeed(), "upf_tdf_ul_enable_disable")
		})
		// TODO: tdf tests are non-exhaustive
	})

	ginkgo.Context("for upf tdf ul table", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)

		addMapping := func(isIPv6 bool, src uint32, dst uint32) {
			req := &upf.UpfTdfUlTableAdd{
				IsAdd:            true,
				IsIPv6:           isIPv6,
				TableID:          src,
				SrcLookupTableID: dst,
			}
			reply := &upf.UpfTdfUlTableAddReply{}
			gomega.Expect(
				f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply),
			).To(gomega.Succeed(), "upf_tdf_ul_table_add")
		}

		getMappings := func(isIPv6 bool) []uint32 {
			req := &upf.UpfTdfUlTable{
				IsIPv6: isIPv6,
			}
			reply := &upf.UpfTdfUlTableReply{}

			gomega.Expect(
				f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply),
			).To(gomega.Succeed(), "upf_tdf_ul_table: mappings_len")
			gomega.Expect(
				reply.MappingsLen,
			).To(gomega.Equal(uint8(len(reply.Mappings))), "upf_tdf_ul_table: mappings_len")
			gomega.Expect(
				reply.MappingsLen%2,
			).To(gomega.Equal(uint8(0)), "upf_tdf_ul_table: mappings_len")
			return reply.Mappings
		}

		ginkgo.It("sets and retrieves table mappings", func() {
			// there should be no ipv6 mappings initially
			mappings := getMappings(true)
			gomega.Expect(mappings).To(gomega.Equal([]uint32{}), "upf_tdf_ul_table")

			addMapping(true, 0, 1001)
			addMapping(true, 1001, 0)

			mappings = getMappings(true)
			gomega.Expect(mappings).To(gomega.Equal([]uint32{0, 1001, 1001, 0}), "upf_tdf_ul_table")

			// there is a mapping for ipv4 initially so we expect it
			mappings = getMappings(false)
			gomega.Expect(mappings).To(gomega.Equal([]uint32{100, 1001}), "upf_tdf_ul_table")

			addMapping(false, 1001, 0)

			mappings = getMappings(false)
			gomega.Expect(mappings).To(gomega.Equal([]uint32{100, 1001, 1001, 0}), "upf_tdf_ul_table")
		})
	})

	ginkgo.Context("for node-id", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)

		callSetNodeID := func(req *upf.UpfSetNodeID) error {
			reply := &upf.UpfSetNodeIDReply{}
			return f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply)
		}

		callGetNodeID := func() (*upf.UpfGetNodeIDReply, error) {
			req := &upf.UpfGetNodeID{}
			reply := &upf.UpfGetNodeIDReply{}
			err := f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply)
			return reply, err
		}

		ginkgo.It("sets and retrieves the node-id", func() {
			ipv4, _ := ip_types.ParseAddress("192.168.42.1")
			ipv6, _ := ip_types.ParseAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

			fqdnStr := "upg.example.com"
			fqdn := util.EncodeFQDN(fqdnStr)
			fqdnLen := uint8(len(fqdn))

			// pass 1: IPv4
			setReq := &upf.UpfSetNodeID{
				Type: uint8(upf.UPF_NODE_TYPE_IPv4),
				IP:   ipv4,
			}
			gomega.Expect(callSetNodeID(setReq)).To(gomega.Succeed(), "upf_set_node_id")

			out, err := f.VPP.Ctl("show upf node-id")
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "show upf node-id")
			gomega.Expect(out).To(gomega.ContainSubstring(ipv4.ToIP().String()), "expected node-id")

			getReply, err := callGetNodeID()
			gomega.Expect(err).To(gomega.BeNil(), "upf_get_node_id")
			gomega.Expect(getReply).To(gomega.Equal(
				&upf.UpfGetNodeIDReply{
					Type:    uint8(upf.UPF_NODE_TYPE_IPv4),
					IP:      ipv4,
					FqdnLen: 0,
					Fqdn:    []byte{},
				}), "upf_get_node_id")

			// pass 2: IPv6
			setReq = &upf.UpfSetNodeID{
				Type: uint8(upf.UPF_NODE_TYPE_IPv6),
				IP:   ipv6,
			}
			gomega.Expect(callSetNodeID(setReq)).To(gomega.Succeed(), "upf_set_node_id")

			out, err = f.VPP.Ctl("show upf node-id")
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "show upf node-id")
			gomega.Expect(out).To(gomega.ContainSubstring(ipv6.ToIP().String()), "expected node-id")

			getReply, err = callGetNodeID()
			gomega.Expect(err).To(gomega.BeNil(), "upf_get_node_id")
			gomega.Expect(getReply).To(gomega.Equal(
				&upf.UpfGetNodeIDReply{
					Type:    uint8(upf.UPF_NODE_TYPE_IPv6),
					IP:      ipv6,
					FqdnLen: 0,
					Fqdn:    []byte{},
				}), "upf_get_node_id")

			// pass 3: FQDN
			setReq = &upf.UpfSetNodeID{
				Type: uint8(upf.UPF_NODE_TYPE_FQDN),
				Fqdn: fqdn,
			}
			gomega.Expect(callSetNodeID(setReq)).To(gomega.Succeed(), "upf_set_node_id")

			out, err = f.VPP.Ctl("show upf node-id")
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "show upf node-id")
			gomega.Expect(out).To(gomega.ContainSubstring(fqdnStr), "expected node-id")

			getReply, err = callGetNodeID()
			gomega.Expect(err).To(gomega.BeNil(), "upf_get_node_id")
			gomega.Expect(getReply).To(gomega.Equal(
				&upf.UpfGetNodeIDReply{
					Type:    uint8(upf.UPF_NODE_TYPE_FQDN),
					IP:      ip_types.Address{},
					FqdnLen: fqdnLen,
					Fqdn:    fqdn,
				}), "upf_get_node_id")
		})
	})

	ginkgo.Context("for policy based routing", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("adds, removes and lists the routing policies", func() {
			policy := &upf.UpfPolicyAddDel{}
			policy.Action = 1
			policy.Identifier = "qwerty"
			policy.NPaths = 1
			rpath := fib_types.FibPath{}
			nhip, err := ip_types.ParseAddress("144.0.0.2")
			gomega.Expect(err).To(gomega.BeNil())
			rpath.Nh.Address.SetIP4(nhip.Un.GetIP4())
			rpath.SwIfIndex = 3
			rpath.Proto = fib_types.FIB_API_PATH_NH_PROTO_IP4
			rpath.Flags = 0
			policy.Paths = append(policy.Paths, rpath)

			policyReply := &upf.UpfPolicyAddDelReply{}
			err = f.VPP.ApiChannel.SendRequest(policy).ReceiveReply(policyReply)
			gomega.Expect(err).To(gomega.BeNil())

			reqCtx := f.VPP.ApiChannel.SendMultiRequest(&upf.UpfPolicyDump{})

			for {
				msg := &upf.UpfPolicyDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).To(gomega.BeNil())
				if stop {
					break
				}
				gomega.Expect(msg.Identifier).To(gomega.BeEquivalentTo(policy.Identifier))
				gomega.Expect(msg.NPaths).To(gomega.BeEquivalentTo(1))
				for i := 0; i < int(msg.NPaths); i++ {
					gomega.Expect(msg.Paths[i].SwIfIndex).To(gomega.BeEquivalentTo(policy.Paths[i].SwIfIndex))
					gomega.Expect(msg.Paths[i].Nh.Address.GetIP4().String()).To(gomega.BeEquivalentTo(policy.Paths[i].Nh.Address.GetIP4().String()))
				}
			}

			policy.Action = 0
			policyReply = &upf.UpfPolicyAddDelReply{}
			err = f.VPP.ApiChannel.SendRequest(policy).ReceiveReply(policyReply)
			gomega.Expect(err).To(gomega.BeNil())

			msg := &upf.UpfPolicyDetails{}
			_, err = reqCtx.ReceiveReply(msg)
			gomega.Expect(err).NotTo(gomega.BeNil())
		})
	})

	ginkgo.Context("for NWIs", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.BeforeEach(func() {
			_, err := f.VPP.Ctl("ip table add 42000")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			_, err = f.VPP.Ctl("ip6 table add 42001")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("adds, removes and lists the NWIs", func() {
			ip, _ := ip_types.ParseAddress("192.168.42.1")
			req := &upf.UpfNwiAddDel{
				Nwi:                   util.EncodeFQDN("testing"),
				IP4TableID:            42000,
				IP6TableID:            42001,
				IpfixPolicy:           []byte("NatEvent"),
				IpfixCollectorIP:      ip,
				IpfixReportInterval:   uint32(7),
				ObservationDomainID:   uint32(42),
				ObservationDomainName: []byte("test"),
				ObservationPointID:    uint64(4242),
				Add:                   1,
			}
			reply := &upf.UpfNwiAddDelReply{}
			err := f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply)
			gomega.Expect(err).To(gomega.BeNil(), "upf_nwi_add_del")

			reqCtx := f.VPP.ApiChannel.SendMultiRequest(&upf.UpfNwiDump{})
			var found bool
			for {
				msg := &upf.UpfNwiDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).To(gomega.BeNil())
				if stop {
					break
				}
				if util.DecodeFQDN(msg.Nwi) != "testing" {
					continue
				}
				gomega.Expect(msg.IP4TableID).To(gomega.Equal(uint32(42000)))
				gomega.Expect(msg.IP6TableID).To(gomega.Equal(uint32(42001)))
				ipfixPolicy := string(bytes.Trim(msg.IpfixPolicy, "\x00"))
				gomega.Expect(ipfixPolicy).To(gomega.Equal("NatEvent"))
				gomega.Expect(msg.IpfixCollectorIP.String()).To(gomega.Equal("192.168.42.1"))
				gomega.Expect(msg.IpfixReportInterval).To(gomega.Equal(uint32(7)))
				gomega.Expect(msg.ObservationDomainID).To(gomega.Equal(uint32(42)))
				obsDomainName := string(bytes.Trim(msg.ObservationDomainName, "\x00"))
				gomega.Expect(obsDomainName).To(gomega.Equal("test"))
				gomega.Expect(msg.ObservationPointID).To(gomega.Equal(uint64(4242)))
				found = true
			}
			gomega.Expect(found).To(gomega.BeTrue(), "upf_nwi_dump")

			out, err := f.VPP.Ctl("show upf nwi")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(out).To(gomega.ContainSubstring(
				"testing, ip4-table-id 42000, ip6-table-id 42001, " +
					"ipfix-policy NatEvent, ipfix-collector-ip 192.168.42.1"))

			req.Add = 0
			reply = &upf.UpfNwiAddDelReply{}
			err = f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply)
			gomega.Expect(err).To(gomega.BeNil())

			reqCtx = f.VPP.ApiChannel.SendMultiRequest(&upf.UpfNwiDump{})
			found = false
			for {
				msg := &upf.UpfNwiDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).To(gomega.BeNil())
				if stop {
					break
				}
				if util.DecodeFQDN(msg.Nwi) != "testing" {
					continue
				}
				found = true
			}
			gomega.Expect(found).To(gomega.BeFalse())

			out, err = f.VPP.Ctl("show upf nwi")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(out).NotTo(gomega.ContainSubstring("testing,"))
		})
	})

	ginkgo.Context("for PFCP endpoint", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)

		// avoid pre-creating a PFCP endpoint and starting a PFCP connection
		f.VPPCfg.SetupCommands = nil
		f.PFCPCfg = nil

		ginkgo.It("lists and removes the PFCP endpoint", func() {
			ipAddr, err := ip_types.ParseAddress("10.1.0.2")
			gomega.Expect(err).ToNot(gomega.HaveOccurred())
			req := &upf.UpfPfcpEndpointAddDel{
				IsAdd:   1,
				TableID: 100,
				IP:      ipAddr,
			}
			reply := &upf.UpfPfcpEndpointAddDelReply{}
			err = f.VPP.ApiChannel.SendRequest(req).ReceiveReply(reply)
			gomega.Expect(err).ToNot(gomega.HaveOccurred(), "upf_pfcp_endpoint_add_del")

			reqCtx := f.VPP.ApiChannel.SendMultiRequest(&upf.UpfPfcpEndpointDump{})
			found := false
			for {
				msg := &upf.UpfPfcpEndpointDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				if stop {
					break
				}
				if msg.IP == req.IP {
					found = true
					gomega.Expect(msg.TableID).To(gomega.BeEquivalentTo(100))
				}
			}
			gomega.Expect(found).To(gomega.BeTrue())

			req.IsAdd = 0
			pfcpEndpointReply := &upf.UpfPfcpEndpointAddDelReply{}
			err = f.VPP.ApiChannel.SendRequest(req).ReceiveReply(pfcpEndpointReply)
			gomega.Expect(err).ToNot(gomega.HaveOccurred())

			reqCtx = f.VPP.ApiChannel.SendMultiRequest(&upf.UpfPfcpEndpointDump{})
			found = false
			for {
				msg := &upf.UpfPfcpEndpointDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).ToNot(gomega.HaveOccurred())
				if stop {
					break
				}
				if msg.IP == req.IP {
					found = true
				}
			}
			gomega.Expect(found).To(gomega.BeFalse())
		})
	})

	ginkgo.Context("for PFCP Session Server", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("configures PFCP server settings", func() {

			sessionServerCfg := &upf.UpfPfcpServerSet{
				FifoSize:    512, // KB
				SegmentSize: 512, // MB
			}
			reply := &upf.UpfPfcpServerSetReply{}

			err := f.VPP.ApiChannel.SendRequest(sessionServerCfg).ReceiveReply(reply)
			// TODO: This will return error, need to change configuration mechanism of UPGMode to binapi
			gomega.Expect(err).NotTo(gomega.BeNil())

			showRequest := &upf.UpfPfcpServerShow{}
			showReply := &upf.UpfPfcpServerShowReply{}
			err = f.VPP.ApiChannel.SendRequest(showRequest).ReceiveReply(showReply)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(showReply.FifoSize).To(gomega.BeEquivalentTo(512)) // KB
			gomega.Expect(showReply.PreallocFifos).To(gomega.BeEquivalentTo(0))
		})

		ginkgo.It("configures PFCP heartbeats", func() {
			hbConfig := &upf.UpfPfcpHeartbeatsSet{
				Retries: 5,
				Timeout: 10,
			}
			reply := &upf.UpfPfcpHeartbeatsSetReply{}
			err := f.VPP.ApiChannel.SendRequest(hbConfig).ReceiveReply(reply)
			gomega.Expect(err).To(gomega.BeNil())

			hbConfigStr, err := f.VPP.Ctl("show upf heartbeat-config")
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(hbConfigStr).To(gomega.ContainSubstring("Timeout: 10"))
			gomega.Expect(hbConfigStr).To(gomega.ContainSubstring("Retries: 5"))

			_, err = f.VPP.Ctl("upf pfcp heartbeat-config timeout 5 retries 15")
			gomega.Expect(err).To(gomega.BeNil())
			hbGetRequest := &upf.UpfPfcpHeartbeatsGet{}
			hbGetReply := &upf.UpfPfcpHeartbeatsGetReply{}
			err = f.VPP.ApiChannel.SendRequest(hbGetRequest).ReceiveReply(hbGetReply)
			gomega.Expect(err).To(gomega.BeNil())
			gomega.Expect(hbGetReply.Timeout).To(gomega.Equal(uint32(5)))
			gomega.Expect(hbGetReply.Retries).To(gomega.Equal(uint32(15)))
		})
	})
})

var _ = ginkgo.Describe("Heartbeats", func() {
	f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
	f.PFCPCfg = nil

	ginkgo.It("are sent at regular intervals after re-association", func() {
		hbConfig := &upf.UpfPfcpHeartbeatsSet{
			Retries: 3,
			Timeout: 2,
		}
		reply := &upf.UpfPfcpHeartbeatsSetReply{}
		err := f.VPP.ApiChannel.SendRequest(hbConfig).ReceiveReply(reply)
		gomega.Expect(err).To(gomega.BeNil())

		for i := 0; i < 5; i++ {
			if i != 0 {
				f.PFCP.HardStop()
			}
			pfcpCfg := framework.DefaultPFCPConfig(*f.VPPCfg)
			// Use different initial seq numbers so as the new
			// AssociationSetupRequests aren't considered to be
			// retransmits
			pfcpCfg.InitialSeq = uint32(i * 10000)
			f.PFCPCfg = &pfcpCfg
			f.PFCPCfg.Namespace = f.VPP.GetNS("cp")
			f.PFCP = pfcp.NewPFCPConnection(*f.PFCPCfg)
			framework.ExpectNoError(f.PFCP.Start(f.VPP.Context(context.Background())))
		}

		time.Sleep(7 * time.Second)
		hbs := f.PFCP.ReceivedHBRequestTimes()
		gomega.Expect(len(hbs)).To(gomega.BeNumerically(">=", 2), "number of heartbeats")
		gomega.Expect(len(hbs)).To(gomega.BeNumerically("<=", 3), "number of heartbeats")
		for n := 1; n < len(hbs); n++ {
			gomega.Expect(hbs[n]).To(
				gomega.BeTemporally("~", hbs[n-1].Add(2*time.Second),
					500*time.Millisecond),
				"heartbeat times")
		}
	})
})

var _ = ginkgo.Describe("Clearing message queue", func() {
	ginkgo.Context("during session deletion", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("should work correctly for sessions being deleted", func() {
			for i := 0; i < 10; i++ {
				seid := startMeasurementSession(f, &framework.SessionConfig{})
				stopAt := time.Now().Add(35 * time.Second)
				for time.Now().Before(stopAt) {
					_, err := f.PFCP.ModifySession(f.VPP.Context(context.Background()), seid, ie.NewQueryURR(ie.NewURRID(1)))
					if err == nil {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					gomega.Expect(errors.Is(err, context.Canceled)).To(gomega.BeFalse())
					framework.Logf("ModifySession() failed (expected): %v", err)
				}
				ginkgo.By("deleting the PFCP session")
				deleteSession(f, seid, false)
			}
		})
	})

	ginkgo.Context("during PFCP Association Release upon timeout", func() {
		var fitHook util.FITHook
		f := framework.NewDefaultFrameworkFIT(framework.UPGModeTDF, framework.UPGIPModeV4, &fitHook)
		fitHook.EnableFault(util.FaultIgnoreHeartbeat)
		ginkgo.It("should work correcty", func() {
			seids := []pfcp.SEID{
				startMeasurementSession(f, &framework.SessionConfig{}),
			}
			var wg sync.WaitGroup
			for i := 1; i <= 2; i++ {
				time.Sleep(50 * time.Millisecond)

				var fitHookInner util.FITHook
				pfcpCfg := framework.DefaultPFCPConfig(*f.VPPCfg)
				pfcpCfg.Namespace = f.VPP.GetNS("cp")
				pfcpCfg.NodeID = fmt.Sprintf("node%d", i)
				pfcpCfg.CNodeIP = f.AddCNodeIP()
				pfcpCfg.FITHook = &fitHookInner
				// make UPG drop this association eventually
				fitHookInner.EnableFault(util.FaultIgnoreHeartbeat)
				pc := pfcp.NewPFCPConnection(pfcpCfg)
				framework.ExpectNoError(pc.Start(f.Context))

				sessionCfg := &framework.SessionConfig{
					IdBase: 1,
					// TODO: using same UE IP multiple times crashes UPG
					// (should be an error instead)
					UEIP: f.AddUEIP(),
					Mode: f.Mode,
				}
				seid, err := pc.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
				framework.ExpectNoError(err)

				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						_, err := pc.ModifySession(f.VPP.Context(context.Background()), seid, ie.NewQueryURR(ie.NewURRID(1)))
						if err != nil {
							framework.Logf("ModifySession() failed (expected): %v", err)
							pc.HardStop()
							break
						}
					}
				}()

				seids = append(seids, seid)
			}
			verifyActiveSessions(f, seids)

			listNodes := func() string {
				var nodes []string
				r, err := f.VPP.Ctl("show upf association")
				framework.ExpectNoError(err)
				for _, l := range strings.Split(r, "\n") {
					if strings.HasPrefix(l, "Node: ") {
						nodes = append(nodes, strings.TrimSpace(l[6:]))
					}
				}
				sort.Strings(nodes)
				return strings.Join(nodes, ",")
			}

			framework.ExpectEqual(listNodes(), "node1,node2,pfcpstub")

			ginkgo.By("Waiting for the main PFCP association to drop while sending requests...")
			stopAt := time.Now().Add(5 * time.Minute)
			for time.Now().Before(stopAt) {
				_, err := f.PFCP.ModifySession(f.VPP.Context(context.Background()), seids[0], ie.NewQueryURR(ie.NewURRID(1)))
				if err != nil {
					framework.Logf("ModifySession() failed (expected): %v", err)
					f.PFCP.HardStop()
					// don't try to stop the PFCPConnection normally
					// in framework's AfterEach
					f.PFCP = nil
					break
				}
				time.Sleep(10 * time.Millisecond)
			}

			gomega.Eventually(listNodes, 2*time.Minute, 5*time.Second).Should(gomega.Equal(""))

			ginkgo.By("Waiting for the extra PFCP associations to drop")
			wg.Wait()

			ginkgo.By("Verifying that all of the active sessions are gone")
			verifyActiveSessions(f, nil)
		})
	})
})

const numPFCPPeers = 10
const sessionsPerPeer = 1

var _ = ginkgo.Describe("Multiple PFCP peers", func() {
	f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
	ginkgo.Context("in SMFSet", func() {
		ginkgo.It("should retransmit in-flight request to new peer", func() {
			hbConfig := &upf.UpfPfcpHeartbeatsSet{
				Retries: 2,
				Timeout: 1,
			}
			reply := &upf.UpfPfcpHeartbeatsSetReply{}
			err := f.VPP.ApiChannel.SendRequest(hbConfig).ReceiveReply(reply)
			gomega.Expect(err).To(gomega.BeNil())

			var conns [3]*pfcp.PFCPConnection
			var reportCh [3]<-chan message.Message
			var pfcpCfgs [4]pfcp.PFCPConfig

			for i := 0; i < 4; i++ {
				pfcpCfgs[i] = framework.DefaultPFCPConfig(*f.VPPCfg)
				pfcpCfgs[i].Namespace = f.VPP.GetNS("cp")
				pfcpCfgs[i].NodeID = fmt.Sprintf("node%d", i)
				pfcpCfgs[i].CNodeIP = f.AddCNodeIP()
				pfcpCfgs[i].RecoveryTimestamp = time.Now().Local().Add(time.Duration(-i) * 24 * time.Hour)
				pfcpCfgs[i].SMFSet = "\x06smfset\x04test"
			}
			for i := 0; i < 3; i++ {
				pc := pfcp.NewPFCPConnection(pfcpCfgs[i])
				framework.ExpectNoError(pc.Start(f.Context))
				conns[i] = pc
				reportCh[i] = pc.AcquireReportCh()
			}
			time.Sleep(2 * time.Second)

			sessionCfg := framework.SessionConfig{
				IdBase:            1,
				UEIP:              f.AddUEIP(),
				Mode:              framework.UPGModeTDF,
				VTime:             1 * time.Second,
				MeasurementPeriod: 15 * time.Second,
			}

			// TODO: also possible to check for order of reports

			cp_seid, err := conns[0].EstablishSession(f.Context, 100, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			// stop new association 0, node should migrate to 1 or 2
			var fitHook util.FITHook
			fitHook.EnableFault(util.FaultNoReportResponse)
			fitHook.EnableFault(util.FaultIgnoreHeartbeat)

			gomega.Expect(conns[1].ShareSession(conns[0], cp_seid)).To(gomega.Succeed())
			gomega.Expect(conns[2].ShareSession(conns[0], cp_seid)).To(gomega.Succeed())

			conns[0].FITHook = &fitHook
			conns[0].Stop()

			type nodeMsg struct {
				id  int
				msg message.Message
			}

			// TODO: replace with func
			resutCh := make(chan nodeMsg, 1)
			go func() {
				select {
				case m := <-reportCh[0]:
					resutCh <- nodeMsg{msg: m, id: 0}
				case m := <-reportCh[1]:
					resutCh <- nodeMsg{msg: m, id: 1}
				case m := <-reportCh[2]:
					resutCh <- nodeMsg{msg: m, id: 2}
				}
			}()

			var cpOwnerNodeId int
			{
				var m nodeMsg
				gomega.Eventually(resutCh, 20*time.Second, 50*time.Millisecond).Should(gomega.Receive(&m))
				framework.ExpectEqual(m.msg.MessageType(), message.MsgTypeSessionReportRequest)
				framework.ExpectNotEqual(m.id, 0, "should not receive on old peer")

				rr := m.msg.(*message.SessionReportRequest)
				gomega.Expect(rr.ReportType).NotTo(gomega.BeNil())
				framework.ExpectEqual(rr.SEID(), uint64(0), "should not have SEID")
				framework.ExpectEqual(rr.OldCPFSEID, conns[0].NewIEFSEID(cp_seid), "should have same old cpfseid")

				cpOwnerNodeId = m.id
			}
			// now create new association 3 in set and stop nodes 1 and 2

			cp_seid += pfcp.CP_SEID_CHANGE_ON_SMF_MIGRATION

			pc3 := pfcp.NewPFCPConnection(pfcpCfgs[3])
			framework.ExpectNoError(pc3.Start(f.Context))
			conn3 := pc3
			reportCh3 := pc3.AcquireReportCh()

			gomega.Expect(conn3.ShareSession(conns[cpOwnerNodeId], cp_seid)).To(gomega.Succeed())

			conns[1].FITHook = &fitHook
			conns[1].Stop()
			conns[2].FITHook = &fitHook
			conns[2].Stop()

			go func() {
				select {
				case m := <-reportCh[0]:
					resutCh <- nodeMsg{msg: m, id: 0}
				case m := <-reportCh[1]:
					resutCh <- nodeMsg{msg: m, id: 1}
				case m := <-reportCh[2]:
					resutCh <- nodeMsg{msg: m, id: 2}
				case m := <-reportCh3:
					resutCh <- nodeMsg{msg: m, id: 3}
				}
			}()

			{
				var m nodeMsg
				gomega.Eventually(resutCh, 20*time.Second, 50*time.Millisecond).Should(gomega.Receive(&m))
				framework.ExpectEqual(m.msg.MessageType(), message.MsgTypeSessionReportRequest)
				framework.ExpectEqual(m.id, 3, "should receive on only peer left")

				rr := m.msg.(*message.SessionReportRequest)
				gomega.Expect(rr.ReportType).NotTo(gomega.BeNil())
				framework.ExpectEqual(rr.SEID(), uint64(0), "should not have SEID")
				framework.ExpectEqual(rr.OldCPFSEID, conns[cpOwnerNodeId].NewIEFSEID(cp_seid), "should have same old cpfseid")
			}

			for _, pc := range conns {
				pc.Stop()
			}
		})
	})

	ginkgo.It("should work correctly", func() {
		var conns [numPFCPPeers]*pfcp.PFCPConnection
		hbConfig := &upf.UpfPfcpHeartbeatsSet{
			Retries: 5,
			Timeout: 1,
		}
		reply := &upf.UpfPfcpHeartbeatsSetReply{}
		err := f.VPP.ApiChannel.SendRequest(hbConfig).ReceiveReply(reply)
		gomega.Expect(err).To(gomega.BeNil())

		for i := 0; i < numPFCPPeers; i++ {
			pfcpCfg := framework.DefaultPFCPConfig(*f.VPPCfg)
			pfcpCfg.Namespace = f.VPP.GetNS("cp")
			pfcpCfg.NodeID = fmt.Sprintf("node%d", i)
			pfcpCfg.CNodeIP = f.AddCNodeIP()
			pfcpCfg.RecoveryTimestamp = time.Now().Local().Add(time.Duration(-i) * 24 * time.Hour)
			pc := pfcp.NewPFCPConnection(pfcpCfg)
			framework.ExpectNoError(pc.Start(f.Context))
			conns[i] = pc
		}
		// time.Sleep(40 * time.Second)
		time.Sleep(10 * time.Second)

		for _, pc := range conns {
			specs := make([]pfcp.SessionOpSpec, sessionsPerPeer)
			for i := 0; i < sessionsPerPeer; i++ {
				scfg := framework.SessionConfig{
					IdBase: 1,
					UEIP:   f.AddUEIP(),
					Mode:   framework.UPGModeTDF,
					VTime:  2 * time.Hour,
				}
				specs[i].IEs = scfg.SessionIEs()

			}
			_, errs := pc.EstablishSessions(context.Background(), specs[:sessionsPerPeer])
			for _, err := range errs {
				framework.ExpectNoError(err)
			}
		}

		for _, pc := range conns {
			pc.Stop()
		}
	})
})

var _ = ginkgo.Describe("FIT Tests", func() {
	var fitHook util.FITHook
	f := framework.NewDefaultFrameworkFIT(framework.UPGModeTDF, framework.UPGIPModeV4, &fitHook)

	ginkgo.Context("Handling Session Report errors", func() {
		ginkgo.It("should drop a session upon a Session Report Response with Session context not found error", func() {
			ginkgo.By("Creating session with an URR that has Monitoring time")
			sessionCfg := &framework.SessionConfig{
				IdBase:            1,
				UEIP:              f.UEIP(),
				Mode:              f.Mode,
				MeasurementPeriod: 3 * time.Second,
			}
			reportCh := f.PFCP.AcquireReportCh()
			_, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			out, err := f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).NotTo(gomega.BeEmpty())

			ginkgo.By("Starting some traffic")
			tg, clientNS, serverNS := newTrafficGen(f, &traffic.UDPPingConfig{
				PacketCount: 50, // 5s
				Retry:       true,
				Delay:       100 * time.Millisecond,
			}, &traffic.SimpleTrafficRec{})
			errCh := tg.Start(f.Context, clientNS, serverNS)

			// injecting fault
			fitHook.EnableFault(util.FaultSessionForgot)

			ginkgo.By("Waiting for the report")
			var msg message.Message
			gomega.Eventually(reportCh, 5*time.Second, 50*time.Millisecond).Should(gomega.Receive(&msg))
			_, err = pfcp.GetMeasurement(msg)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			ginkgo.By("Checking if session got deleted")
			out, err = f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).To(gomega.BeEmpty(), "Session should be deleted after receiving 'context not found' error")

			ginkgo.By("Waiting for trafficgen to finish...")
			gomega.Eventually(errCh, 10*time.Second, 50*time.Millisecond).Should(gomega.Receive(&err))
			framework.ExpectNoError(err, "trafficgen error")
		})
	})
})

var _ = ginkgo.Describe("[Reporting]", func() {
	ginkgo.Context("Quota Validity Time", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("should generate usage report upon expiry", func() {
			ginkgo.By("Creating session with an URR")
			sessionCfg := &framework.SessionConfig{
				IdBase: 1,
				UEIP:   f.UEIP(),
				Mode:   f.Mode,
				VTime:  10 * time.Second,
			}
			reportCh := f.PFCP.AcquireReportCh()
			_, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			var m message.Message
			gomega.Eventually(reportCh, 12*time.Second, 50*time.Millisecond).Should(gomega.Receive(&m))
			framework.ExpectEqual(m.MessageType(), message.MsgTypeSessionReportRequest)

			rr := m.(*message.SessionReportRequest)
			gomega.Expect(rr.ReportType).NotTo(gomega.BeNil())
			_, err = rr.ReportType.ReportType()
			framework.ExpectNoError(err)
			gomega.Expect(rr.ReportType.HasUPIR()).To(gomega.BeFalse())
			gomega.Expect(rr.ReportType.HasERIR()).To(gomega.BeFalse())
			gomega.Expect(rr.ReportType.HasUSAR()).To(gomega.BeTrue())
			gomega.Expect(rr.ReportType.HasDLDR()).To(gomega.BeFalse())

			gomega.Expect(rr.UsageReport).To(gomega.HaveLen(2))
			for _, ur := range rr.UsageReport {
				urt, err := ur.FindByType(ie.UsageReportTrigger)
				framework.ExpectNoError(err)
				gomega.Expect(len(urt.Payload)).To(gomega.BeNumerically(">=", 3))
				gomega.Expect(urt.Payload[2] & 8).NotTo(gomega.BeZero()) // QUVTI bit is set
			}
		})
	})

	ginkgo.Context("Remove URR", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("should generate usage report", func() {
			ginkgo.By("Removing URRs from session should trigger Usage Report")
			sessionCfg := &framework.SessionConfig{
				IdBase:      1,
				UEIP:        f.UEIP(),
				Mode:        f.Mode,
				VolumeQuota: 100000,
				NoURRs:      false,
			}
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)
			ginkgo.By("Starting some traffic")
			tg, clientNS, serverNS := newTrafficGen(f, &traffic.UDPPingConfig{
				PacketCount: 10, // 10s
				Retry:       true,
				Delay:       100 * time.Millisecond,
			}, &traffic.SimpleTrafficRec{})
			tg.Start(f.Context, clientNS, serverNS)

			time.Sleep(time.Second * 5)

			_, err = f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			ginkgo.By("Updating session by removing FARs/PDRs/URRs for forwarding")
			modifyIEs := sessionCfg.DeletePDRs()
			modifyIEs = append(modifyIEs, sessionCfg.DeleteFARs()...)
			modifyIEs = append(modifyIEs, sessionCfg.DeleteURRs()...)
			m, err := f.PFCP.ModifySession(
				f.VPP.Context(context.Background()), seid,
				modifyIEs...)
			framework.ExpectNoError(err, "ModifySession")
			// Two reports for each URRs
			gomega.Expect(m.Reports).To(gomega.HaveLen(2))
			gomega.Expect(m.Reports[1]).To(gomega.HaveLen(1))
			gomega.Expect(m.Reports[2]).To(gomega.HaveLen(1))
			gomega.Expect(m.Reports[1][0].TotalVolume).NotTo(gomega.BeNil())
			gomega.Expect(*m.Reports[1][0].TotalVolume).NotTo(gomega.BeZero())

		})
	})

	ginkgo.Context("Monitoring time", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("should generate split report", func() {
			ginkgo.By("Creating session with an URR that has Monitoring time")
			monitoringTime := time.Now().Add(4 * time.Second).Round(time.Second)
			sessionCfg := &framework.SessionConfig{
				IdBase:            1,
				UEIP:              f.UEIP(),
				Mode:              f.Mode,
				MonitoringTime:    monitoringTime,
				MeasurementPeriod: 3 * time.Second,
			}
			reportCh := f.PFCP.AcquireReportCh()
			_, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			out, err := f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).To(gomega.ContainSubstring("Monitoring Time"))

			ginkgo.By("Starting some traffic")
			tg, clientNS, serverNS := newTrafficGen(f, &traffic.UDPPingConfig{
				PacketCount: 50, // 5s
				Retry:       true,
				Delay:       100 * time.Millisecond,
			}, &traffic.SimpleTrafficRec{})
			errCh := tg.Start(f.Context, clientNS, serverNS)

			ginkgo.By("Waiting for the 1st report (no split)...")
			var msg message.Message
			gomega.Eventually(reportCh, 5*time.Second, 50*time.Millisecond).Should(gomega.Receive(&msg))
			m, err := pfcp.GetMeasurement(msg)
			framework.ExpectNoError(err, "GetMeasurement")
			gomega.Expect(m.Reports[1]).To(gomega.HaveLen(1),
				"1 report expected for URR 1 (no splits)")
			gomega.Expect(m.Reports[1][0].TotalVolume).NotTo(gomega.BeNil())
			gomega.Expect(*m.Reports[1][0].TotalVolume).NotTo(gomega.BeZero())
			firstUL := *m.Reports[1][0].UplinkVolume
			firstDL := *m.Reports[1][0].DownlinkVolume

			ginkgo.By("Waiting for the 2nd report (split)...")
			gomega.Eventually(reportCh, 5*time.Second, 50*time.Millisecond).Should(gomega.Receive(&msg))
			m, err = pfcp.GetMeasurement(msg)
			framework.ExpectNoError(err, "GetMeasurement")
			gomega.Expect(m.Reports[1]).To(gomega.HaveLen(2),
				"2 reports expected for URR 1 (split report)")

			out, err = f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).NotTo(gomega.ContainSubstring("Monitoring Time"),
				"Monitoring Time in the session after the report should be gone")

			ginkgo.By("Waiting for trafficgen to finish...")
			gomega.Eventually(errCh, 10*time.Second, 50*time.Millisecond).Should(gomega.Receive(&err))
			framework.ExpectNoError(err, "trafficgen error")

			beforeSplit := m.Reports[1][0]
			afterSplit := m.Reports[1][1]
			if beforeSplit.StartTime.After(m.Reports[1][1].StartTime) {
				beforeSplit, afterSplit = afterSplit, beforeSplit
			}
			gomega.Expect(beforeSplit.StartTime.Before(beforeSplit.EndTime)).To(gomega.BeTrue())
			gomega.Expect(afterSplit.StartTime.Before(afterSplit.EndTime)).To(gomega.BeTrue())
			gomega.Expect(beforeSplit.EndTime).To(gomega.Equal(monitoringTime))
			gomega.Expect(afterSplit.StartTime).To(gomega.Equal(monitoringTime))
			gomega.Expect(beforeSplit.TotalVolume).NotTo(gomega.BeNil())
			gomega.Expect(afterSplit.TotalVolume).NotTo(gomega.BeNil())

			ul, dl := getTrafficCountsFromCapture(f, layers.IPProtocolUDP, nil)
			framework.ExpectEqual(firstUL+*beforeSplit.UplinkVolume+*afterSplit.UplinkVolume, ul,
				"uplink volume")
			framework.ExpectEqual(firstDL+*beforeSplit.DownlinkVolume+*afterSplit.DownlinkVolume, dl,
				"downlink volume")
		})

		ginkgo.It("should properly handle monitoring time change with a pending split report", func() {
			ginkgo.By("Creating session with an URR that has Monitoring time")
			startTime := time.Now()
			monitoringTimes := []time.Time{startTime.Add(3 * time.Second).Round(time.Second)}
			sessionCfg := &framework.SessionConfig{
				IdBase:         1,
				UEIP:           f.UEIP(),
				Mode:           f.Mode,
				MonitoringTime: monitoringTimes[0],
				// request a report _after_ the monitoring time
				MeasurementPeriod: 8 * time.Second,
			}
			reportCh := f.PFCP.AcquireReportCh()
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			out, err := f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).To(gomega.ContainSubstring("Monitoring Time"))

			ginkgo.By("Starting some traffic")
			tg, clientNS, serverNS := newTrafficGen(f, &traffic.UDPPingConfig{
				PacketCount: 180, // 18s
				Retry:       true,
				Delay:       100 * time.Millisecond,
			}, &traffic.SimpleTrafficRec{})
			errCh := tg.Start(f.Context, clientNS, serverNS)

			ginkgo.By("Waiting for the monitoring time...")
			now := time.Now()
			gomega.Expect(now.Before(sessionCfg.MonitoringTime)).To(gomega.BeTrue())
			time.Sleep(sessionCfg.MonitoringTime.Add(2 * time.Second).Sub(now))

			ginkgo.By("Updating monitoring time in the session")
			// note that measurement period is reset here, and we want the new
			// monitoring time to be after the report
			sessionCfg.MonitoringTime = time.Now().Add(10 * time.Second).Truncate(time.Second)
			monitoringTimes = append(monitoringTimes, sessionCfg.MonitoringTime)
			_, err = f.PFCP.ModifySession(
				f.VPP.Context(context.Background()), seid,
				sessionCfg.UpdateURRs()...)
			framework.ExpectNoError(err, "ModifySession")

			ginkgo.By("Waiting for the 1st report (split)...")
			var msg message.Message
			gomega.Eventually(reportCh, 20*time.Second, 50*time.Millisecond).Should(gomega.Receive(&msg))

			m, err := pfcp.GetMeasurement(msg)
			framework.ExpectNoError(err, "GetMeasurement")
			gomega.Expect(m.Reports[1]).To(gomega.HaveLen(2),
				"2 reports expected for URR 1 (split report)")

			beforeSplit := []pfcp.PFCPReport{m.Reports[1][0]}
			afterSplit := []pfcp.PFCPReport{m.Reports[1][1]}

			out, err = f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).To(gomega.ContainSubstring("Monitoring Time"),
				"Monitoring Time in the session after the 1st report")

			ginkgo.By("Waiting for the 2nd report (split)...")
			gomega.Eventually(reportCh, 20*time.Second, 50*time.Millisecond).Should(gomega.Receive(&msg))

			framework.Logf("Elapsed time since session setup: %v", time.Now().Sub(startTime))

			m, err = pfcp.GetMeasurement(msg)
			framework.ExpectNoError(err, "GetMeasurement")
			gomega.Expect(m.Reports[1]).To(gomega.HaveLen(2),
				"2 reports expected for URR 1 (split report)")

			beforeSplit = append(beforeSplit, m.Reports[1][0])
			afterSplit = append(afterSplit, m.Reports[1][1])

			out, err = f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).NotTo(gomega.ContainSubstring("Monitoring Time"),
				"Monitoring Time in the session after the 2nd report should be gone")

			ginkgo.By("Waiting for trafficgen to finish...")
			gomega.Eventually(errCh, 10*time.Second, 50*time.Millisecond).Should(gomega.Receive(&err))
			framework.ExpectNoError(err, "trafficgen error")

			var totalUplink, totalDownlink uint64
			for n, before := range beforeSplit {
				after := afterSplit[n]
				if before.StartTime.After(m.Reports[1][1].StartTime) {
					beforeSplit, afterSplit = afterSplit, beforeSplit
				}
				gomega.Expect(before.StartTime.Before(before.EndTime)).To(gomega.BeTrue())
				gomega.Expect(after.StartTime.Before(after.EndTime)).To(gomega.BeTrue())
				gomega.Expect(before.EndTime).To(gomega.Equal(monitoringTimes[n]))
				gomega.Expect(after.StartTime).To(gomega.Equal(monitoringTimes[n]))
				gomega.Expect(before.TotalVolume).NotTo(gomega.BeNil(), "total volume before (report %d)", n)
				framework.ExpectEqual(*before.UplinkVolume+*before.DownlinkVolume,
					*before.TotalVolume, "bad total volume (split %d)", n)
				gomega.Expect(after.TotalVolume).NotTo(gomega.BeNil(), "total volume after (report %d)", n)
				framework.ExpectEqual(*after.UplinkVolume+*after.DownlinkVolume,
					*after.TotalVolume, "bad total volume (split %d)", n)

				gomega.Expect(before.UplinkVolume).NotTo(gomega.BeNil())
				gomega.Expect(before.DownlinkVolume).NotTo(gomega.BeNil())
				gomega.Expect(after.UplinkVolume).NotTo(gomega.BeNil())
				gomega.Expect(after.DownlinkVolume).NotTo(gomega.BeNil())
				totalUplink += *before.UplinkVolume + *after.UplinkVolume
				totalDownlink += *before.DownlinkVolume + *after.DownlinkVolume
			}

			ul, dl := getTrafficCountsFromCapture(f, layers.IPProtocolUDP, nil)
			framework.ExpectEqual(totalUplink, ul, "uplink volume")
			framework.ExpectEqual(totalDownlink, dl, "downlink volume")
		})

		ginkgo.It("should drop the session instead of creating 2nd pending split", func() {
			ginkgo.By("Creating session with an URR that has Monitoring time")
			startTime := time.Now()
			monitoringTimes := []time.Time{startTime.Add(2 * time.Second).Round(time.Second)}
			sessionCfg := &framework.SessionConfig{
				IdBase:         1,
				UEIP:           f.UEIP(),
				Mode:           f.Mode,
				MonitoringTime: monitoringTimes[0],
				// make measurement period large enough for
				// the pending split reports to "pile up"
				MeasurementPeriod: 30 * time.Second,
			}
			reportCh := f.PFCP.AcquireReportCh()
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)
			seidHex := fmt.Sprintf("0x%016x", seid)

			out, err := f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).To(gomega.ContainSubstring("Monitoring Time"))
			gomega.Expect(string(out)).To(gomega.ContainSubstring(seidHex))

			ginkgo.By("Starting some traffic")
			tg, clientNS, serverNS := newTrafficGen(f, &traffic.UDPPingConfig{
				PacketCount: 180, // 30s, but will be stopped when VPP exits
				Retry:       true,
				Delay:       100 * time.Millisecond,
				Burst:       100,
			}, &traffic.SimpleTrafficRec{})
			tg.Start(f.Context, clientNS, serverNS)

			ginkgo.By("Waiting for 1st monitoring time...")
			now := time.Now()
			gomega.Expect(now.Before(sessionCfg.MonitoringTime)).To(gomega.BeTrue())
			time.Sleep(sessionCfg.MonitoringTime.Add(2 * time.Second).Sub(now))

			ginkgo.By("Updating monitoring time in the session")
			// note that measurement period is reset here, and we want the new
			// monitoring time to be after the report
			sessionCfg.MonitoringTime = time.Now().Add(2 * time.Second).Truncate(time.Second)
			monitoringTimes = append(monitoringTimes, sessionCfg.MonitoringTime)
			_, err = f.PFCP.ModifySession(
				f.VPP.Context(context.Background()), seid,
				sessionCfg.UpdateURRs()...)
			framework.ExpectNoError(err, "ModifySession")

			ginkgo.By("Waiting for 2nd monitoring time...")
			now = time.Now()
			gomega.Expect(now.Before(sessionCfg.MonitoringTime)).To(gomega.BeTrue())
			time.Sleep(sessionCfg.MonitoringTime.Add(3 * time.Second).Sub(now))

			ginkgo.By("Waiting for the PSDBU report...")
			var msg message.Message
			gomega.Eventually(reportCh, 20*time.Second, 50*time.Millisecond).Should(gomega.Receive(&msg))
			// 4 reports as a split still occurs
			verifyPSDBU(msg, 4)
			verifyNoSession(f, seid)
		})
	})

	ginkgo.Context("Quota", func() {
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("should not cause problems after adding a redirect after exhaustion [NAT]", func() {
			ginkgo.By("Creating session with volume quota")
			setupNAT(f)
			sessionCfg := &framework.SessionConfig{
				IdBase:      1,
				UEIP:        f.UEIP(),
				Mode:        f.Mode,
				VolumeQuota: 1024,
				// request a report _after_ the monitoring time
			}
			sessionCfg.NatPoolName = "testing"
			reportCh := f.PFCP.AcquireReportCh()
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			out, err := f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(string(out)).To(gomega.ContainSubstring("1024"))

			ginkgo.By("Starting some traffic")
			tg, clientNS, serverNS := newTrafficGen(f, &traffic.HTTPConfig{
				ChunkCount: 380, // 18s
				Retry:      true,
				ChunkDelay: 100 * time.Millisecond,
			}, &traffic.SimpleTrafficRec{})
			tg.Start(f.Context, clientNS, serverNS)

			ginkgo.By("Expecting report to be happen due to Volume Quota Exhausted")
			var msg message.Message
			gomega.Eventually(reportCh, 20*time.Second, 50*time.Millisecond).Should(gomega.Receive(&msg))
			_, err = pfcp.GetMeasurement(msg)
			framework.ExpectNoError(err, "GetMeasurement")

			ginkgo.By("Updating session by removing FARs/PDRs/URRs for forwarding")
			modifyIEs := sessionCfg.DeletePDRs()
			modifyIEs = append(modifyIEs, sessionCfg.DeleteFARs()...)
			modifyIEs = append(modifyIEs, sessionCfg.DeleteURRs()...)
			_, err = f.PFCP.ModifySession(
				f.VPP.Context(context.Background()), seid,
				modifyIEs...)
			framework.ExpectNoError(err, "ModifySession")
			out, err = f.VPP.Ctl("show upf session")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			sessionCfg.NoURRs = true
			sessionCfg.Redirect = true
			modifyIEs = sessionCfg.CreatePDRs()
			modifyIEs = append(modifyIEs, sessionCfg.CreateFARs(pfcp.ApplyAction_FORW)...)
			_, err = f.PFCP.ModifySession(f.VPP.Context(context.Background()), seid, modifyIEs...)
			framework.ExpectNoError(err, "ModifySession")
			time.Sleep(time.Second * 5)

			ginkgo.By("Verifying redirects...")
			runTrafficGen(f, &traffic.RedirectConfig{
				RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
				RedirectResponseSubstr: "<title>Redirection</title>",
			}, &traffic.PreciseTrafficRec{})
		})
	})
})

const leakTestNumSessions = 10000
const leakTestNumIterations = 3

var _ = ginkgo.Describe("Multiple PFCP Sessions", func() {
	ginkgo.Context("[TDF]", func() {
		// FIXME: these tests may crash UPG in UPGIPModeV6 (bad PFCP requests)
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		ginkgo.It("should not leak memory", func() {
			ginkgo.By("starting memory trace")
			_, err := f.VPP.Ctl("memory-trace main-heap on")
			framework.ExpectNoError(err)
			var ueIPs []net.IP
			for i := 0; i < leakTestNumSessions; i++ {
				ueIPs = append(ueIPs, f.AddUEIP())
			}
			for i := 0; i < leakTestNumIterations; i++ {
				framework.Logf("creating %d sessions", leakTestNumSessions)
				sessionCfgs := make([]*framework.SessionConfig, leakTestNumSessions)
				specs := make([]pfcp.SessionOpSpec, leakTestNumSessions)
				for j := 0; j < leakTestNumSessions; j++ {
					sessionCfgs[j] = &framework.SessionConfig{
						IdBase:  1,
						UEIP:    ueIPs[j],
						Mode:    f.Mode,
						AppName: framework.HTTPAppName,
						// There was a bug in free_far() at some point
						// so it was failing to free redirect information
						Redirect: true,
					}
					specs[j].IEs = sessionCfgs[j].SessionIEs()
				}

				seids, errs := f.PFCP.EstablishSessions(f.Context, specs)
				for _, err := range errs {
					framework.ExpectNoError(err)
				}

				framework.Logf("disabling redirects")
				for j := 0; j < leakTestNumSessions; j++ {
					sessionCfgs[j].Redirect = false
					specs[j].SEID = seids[j]
					specs[j].IEs = append(
						sessionCfgs[j].DeleteFARs(),
						sessionCfgs[j].CreateFARs(pfcp.ApplyAction_FORW)...)
				}
				_, errs = f.PFCP.ModifySessions(f.Context, specs)
				for _, err := range errs {
					framework.ExpectNoError(err)
				}

				framework.Logf("enabling redirects")
				for j := 0; j < leakTestNumSessions; j++ {
					sessionCfgs[j].Redirect = true
					specs[j].SEID = seids[j]
					specs[j].IEs = append(
						sessionCfgs[j].DeleteFARs(),
						sessionCfgs[j].CreateFARs(pfcp.ApplyAction_FORW)...)
				}
				_, errs = f.PFCP.ModifySessions(f.Context, specs)
				for _, err := range errs {
					framework.ExpectNoError(err)
				}

				framework.Logf("deleting %d sessions", leakTestNumSessions)
				deleteSessions(f, seids, false)
			}

			ginkgo.By("Waiting 40 seconds for the queues to be emptied")
			time.Sleep(40 * time.Second)

			memTraceOut, err := f.VPP.Ctl("show memory main-heap")
			framework.ExpectNoError(err)

			parsed, err := vpp.ParseMemoryTrace(memTraceOut)
			framework.ExpectNoError(err)
			gomega.Expect(parsed.FindSuspectedLeak("pfcp", 2000)).To(gomega.BeFalse(),
				"session-related memory leak detected")
		})

		ginkgo.It("should not be allowed to conflict on UE IPs and drop the older conflicting session", func() {
			sessionCfg := &framework.SessionConfig{
				IdBase: 1,
				UEIP:   f.UEIP(),
				Mode:   f.Mode,
			}
			reportCh := f.PFCP.AcquireReportCh()
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)
			// with older UPG versions, the duplicate session creation attempts
			// succeed till some amount of sessions is reached (about 256), after
			// which it crashes
			unexpectedSuccess := false
			var newSEID pfcp.SEID
			for i := 0; i < 1000; i++ {
				newSEID = f.PFCP.NewSEID()
				_, err := f.PFCP.EstablishSession(f.Context, newSEID, sessionCfg.SessionIEs()...)
				if err == nil {
					unexpectedSuccess = true
				} else {
					verifyPFCPError(err, ie.CauseRuleCreationModificationFailure, newSEID, 2,
						"PDR ID 2, duplicate UE IP")
					break
				}
			}
			gomega.Expect(unexpectedSuccess).To(gomega.BeFalse(), "EstablishSession succeeded unexpectedly")
			var m message.Message
			gomega.Eventually(reportCh, 10*time.Second, 50*time.Millisecond).Should(gomega.Receive(&m))
			// Expecting a "PFCP Session Deleted By the UP function" (PSDBU) report
			verifyPSDBU(m, 2)
			verifyNoSession(f, seid)
			verifyNoSession(f, newSEID)
		})

		ginkgo.It("should not be allowed to conflict on UE IPs and drop the older conflicting session [no URRs]", func() {
			sessionCfg := &framework.SessionConfig{
				IdBase: 1,
				UEIP:   f.UEIP(),
				Mode:   f.Mode,
				NoURRs: true,
			}
			reportCh := f.PFCP.AcquireReportCh()
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			var newSEID pfcp.SEID
			newSEID = f.PFCP.NewSEID()
			_, err = f.PFCP.EstablishSession(f.Context, newSEID, sessionCfg.SessionIEs()...)
			verifyPFCPError(err, ie.CauseRuleCreationModificationFailure, newSEID, 2,
				"PDR ID 2, duplicate UE IP")

			var m message.Message
			gomega.Eventually(reportCh, 10*time.Second, 50*time.Millisecond).Should(gomega.Receive(&m))
			framework.ExpectEqual(m.MessageType(), message.MsgTypeSessionReportRequest)

			rr := m.(*message.SessionReportRequest)
			gomega.Expect(rr.ReportType).NotTo(gomega.BeNil())
			_, err = rr.ReportType.ReportType()
			framework.ExpectNoError(err)
			gomega.Expect(rr.ReportType.HasUPIR()).To(gomega.BeFalse())
			gomega.Expect(rr.ReportType.HasERIR()).To(gomega.BeFalse())
			gomega.Expect(rr.ReportType.HasUSAR()).To(gomega.BeFalse())
			gomega.Expect(rr.ReportType.HasDLDR()).To(gomega.BeFalse())
			// FIXME: UISR bit is not yet handled by go-pfcp
			rt, _ := rr.ReportType.ReportType()
			gomega.Expect(rt & 0x40).NotTo(gomega.BeZero())

			gomega.Expect(rr.PFCPSRReqFlags).NotTo(gomega.BeNil())
			gomega.Expect(rr.PFCPSRReqFlags.HasPSDBU()).To(gomega.BeTrue())

			gomega.Expect(rr.UsageReport).To(gomega.HaveLen(0))

			verifyNoSession(f, seid)
			verifyNoSession(f, newSEID)
		})

		ginkgo.It("should not be allowed to conflict on SEIDs", func() {
			sessionCfg := &framework.SessionConfig{
				IdBase: 1,
				UEIP:   f.UEIP(),
				Mode:   f.Mode,
			}
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)

			f.PFCP.ForgetSession(seid)
			sessionCfg.UEIP = f.AddUEIP()
			_, err = f.PFCP.EstablishSession(f.Context, seid, sessionCfg.SessionIEs()...)
			verifyPFCPError(err, ie.CauseRequestRejected, seid, 0, "Duplicate F-SEID")
		})
	})

	ginkgo.Context("[PGW]", func() {
		f := framework.NewDefaultFramework(framework.UPGModePGW, framework.UPGIPModeV4)
		ginkgo.It("should not be allowed to conflict on GTPU tunnels", func() {
			sessionCfg := &framework.SessionConfig{
				IdBase:     1,
				UEIP:       f.UEIP(),
				Mode:       f.Mode,
				TEIDPGWs5u: framework.TEIDPGWs5u,
				TEIDSGWs5u: framework.TEIDSGWs5u,
				PGWIP:      f.VPPCfg.GetVPPAddress("grx").IP,
				SGWIP:      f.VPPCfg.GetNamespaceAddress("grx").IP,
			}
			seid, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)
			defer deleteSession(f, seid, true)

			// Trying to create a conflicting session should cause an error
			sessionCfg = &framework.SessionConfig{
				IdBase:     1,
				UEIP:       f.AddUEIP(),
				Mode:       f.Mode,
				TEIDPGWs5u: framework.TEIDPGWs5u,
				TEIDSGWs5u: framework.TEIDSGWs5u,
				PGWIP:      f.VPPCfg.GetVPPAddress("grx").IP,
				SGWIP:      f.VPPCfg.GetNamespaceAddress("grx").IP,
			}
			_, err = f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			verifyPFCPError(err, ie.CauseRuleCreationModificationFailure, 0, 1,
				"PDR ID 1, can't handle F-TEID")

			sessionCfg.TEIDPGWs5u += 10
			seid1, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)
			deleteSession(f, seid1, true)
		})
	})
})

var _ = ginkgo.Describe("Error handling", func() {
	f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
	ginkgo.It("FAR drops a packet", func() {
		ginkgo.By("Configuring session")
		sessionCfg := &framework.SessionConfig{
			IdBase:      1,
			UEIP:        f.UEIP(),
			Mode:        f.Mode,
			VolumeQuota: 100000,
			NoURRs:      true,
		}
		ies := sessionCfg.CreatePDRs()
		ies = append(ies, sessionCfg.CreateFARs(pfcp.ApplyAction_DROP)...)

		_, err := f.PFCP.EstablishSession(f.Context, 0, ies...)
		framework.ExpectNoError(err)
		ginkgo.By("Starting some traffic")
		tg, clientNS, serverNS := newTrafficGen(f, &traffic.UDPPingConfig{
			PacketCount: 1,
			Retry:       false,
			Delay:       100 * time.Millisecond,
		}, &traffic.SimpleTrafficRec{})
		tg.Start(f.Context, clientNS, serverNS)

		time.Sleep(time.Second * 1)

		output, err := f.VPP.Ctl("show error")
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		// remove extra spaces from between output lines
		var errors []string
		for _, line := range strings.Split(output, "\n") {
			errors = append(errors, strings.Join(strings.Fields(line), " "))
		}

		// since we push 1 packet, there should be one dropped
		gomega.Expect(errors).To(gomega.ContainElement("1 upf-ip4-forward FAR action drop error"))
	})
})

var _ = ginkgo.Describe("PGW Error indication", func() {
	f := framework.NewDefaultFramework(framework.UPGModePGW, framework.UPGIPModeV4)
	ginkgo.It("Error indication for deleted session", func() {
		ginkgo.By("Configuring session")

		var sessionCfgs []framework.SessionConfig
		var seids []pfcp.SEID

		// Create another session to trigger crash
		ueIPs := []net.IP{f.UEIP(), f.AddUEIP()}
		for i, ueIP := range ueIPs {
			sessionCfgs = append(sessionCfgs, framework.SessionConfig{
				IdBase:      1,
				UEIP:        ueIP,
				Mode:        f.Mode,
				VolumeQuota: 100000000,
				TEIDPGWs5u:  framework.TEIDPGWs5u + uint32(i),
				TEIDSGWs5u:  framework.TEIDSGWs5u + uint32(i),
				PGWIP:       f.VPPCfg.GetVPPAddress("grx").IP,
				SGWIP:       f.VPPCfg.GetNamespaceAddress("grx").IP,
			})
			seids = append(seids, f.PFCP.NewSEID())
		}

		for i := range sessionCfgs {
			_, err := f.PFCP.EstablishSession(f.Context, seids[i], sessionCfgs[i].SessionIEs()...)
			framework.ExpectNoError(err)
		}

		ginkgo.By("Starting some traffic")
		tg, clientNS, serverNS := newTrafficGen(f, &traffic.UDPPingConfig{
			PacketCount: 5,
			Retry:       false,
			Delay:       10 * time.Millisecond,
		}, &traffic.SimpleTrafficRec{})
		tg.Start(f.Context, clientNS, serverNS)

		ginkgo.By("Sending error indication")

		stopSpam := make(chan struct{}, 1)

		spamErrorsIndications := func() {
			for {
				select {
				case _, closed := <-stopSpam:
					if closed {
						return
					}
				default:
					err := f.GTPUs[0].SendErrorIndication(0, 0,
						gtpuie.NewTEIDDataI(sessionCfgs[0].TEIDSGWs5u),
						gtpuie.NewGSNAddress(f.VPPCfg.GetNamespaceAddress("grx").IP.String()),
					)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					time.Sleep(time.Millisecond)
				}
			}
		}
		go spamErrorsIndications()

		f.PFCP.DeleteSession(f.Context, seids[0])
		time.Sleep(time.Second / 2)
		f.PFCP.DeleteSession(f.Context, seids[1])
		close(stopSpam)
		time.Sleep(10 * time.Second)
	})
})

var _ = ginkgo.Describe("Error handling", func() {
	f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)

	ginkgo.It("should be done correctly with unknown Forwarding Policy when creating a session", func() {
		sessionCfg := &framework.SessionConfig{
			IdBase:             1,
			UEIP:               f.UEIP(),
			Mode:               f.Mode,
			ForwardingPolicyID: "nosuchpolicy",
		}
		seid := f.PFCP.NewSEID()
		_, err := f.PFCP.EstablishSession(f.Context, seid, sessionCfg.SessionIEs()...)
		verifyPFCPError(err, ie.CauseInvalidForwardingPolicy, seid, 1,
			"FAR ID 1, forwarding policy 'nosuchpolicy' not configured")
	})

	ginkgo.It("should be done correctly with unknown Forwarding Policy when modifying a session", func() {
		sessionCfg := &framework.SessionConfig{
			IdBase: 1,
			UEIP:   f.UEIP(),
			Mode:   f.Mode,
		}
		seid := f.PFCP.NewSEID()
		_, err := f.PFCP.EstablishSession(f.Context, seid, sessionCfg.SessionIEs()...)
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		modIE := ie.NewUpdateFAR(
			ie.NewFARID(1),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
				ie.NewNetworkInstance(framework.EncodeAPN("sgi")),
				ie.NewForwardingPolicy("nosuchpolicy")))
		_, err = f.PFCP.ModifySession(f.Context, seid, modIE)
		verifyPFCPError(err, ie.CauseInvalidForwardingPolicy, seid, 1,
			"FAR ID 1, forwarding policy 'nosuchpolicy' not configured")
	})

	ginkgo.It("should be done correctly for NAT", func() {
		sessionCfg := &framework.SessionConfig{
			IdBase:      1,
			UEIP:        f.UEIP(),
			Mode:        f.Mode,
			NatPoolName: "nosuchpool",
		}
		seid := f.PFCP.NewSEID()
		_, err := f.PFCP.EstablishSession(f.Context, seid, sessionCfg.SessionIEs()...)
		verifyPFCPError(err, ie.CauseRuleCreationModificationFailure, seid, 1,
			"FAR ID 1, Error creating NAT binding for pool 'nosuchpool'")
	})
})

func describeMTU(mode framework.UPGMode, ipMode framework.UPGIPMode) {
	ginkgo.Describe("[MTU corner cases]", func() {
		var seid pfcp.SEID

		// TODO: framework should have Clone() method
		// that makes deep copy of the configs (or re-generates them)

		// TODO: There is a need to check maximum MTU per XDP driver
		// might be added as a separate test of fixed in this one

		var startupCfg vpp.VPPStartupConfig
		startupCfg.SetFromEnv()

		f := framework.NewDefaultFramework(mode, ipMode)
		for i := range f.VPPCfg.Namespaces {
			f.VPPCfg.Namespaces[i].MTU = 1500
		}
		f.GTPUMTU = 9000

		ginkgo.BeforeEach(func() {
			seid = startMeasurementSession(f, &framework.SessionConfig{})
		})

		ginkgo.JustAfterEach(func() {
			deleteSession(f, seid, true)
		})

		ginkgo.It("passes UDP traffic [8000 byte datagrams]", func() {
			// TODO: verify 'too large' error w/o setsockopt
			runTrafficGen(f, &traffic.UDPPingConfig{
				// fragmented after GTP-U encap
				PacketSize: 8000,
				// clear DF bit
				NoMTUDiscovery: true,
			}, &traffic.PreciseTrafficRec{})
			// FIXME: capture analyzer should be able to reassemble the
			// fragments
			// verifyNonAppMeasurement(f, ms, layers.IPProtocolUDP)
		})

		ginkgo.It("passes UDP traffic [10000 byte datagrams]", func() {
			runTrafficGen(f, &traffic.UDPPingConfig{
				// fragmented before & after GTP-U encap
				PacketSize: 10000,
				// No need for NoMTUDiscovery here as
				// the packets are larger than UE's MTU
			}, &traffic.PreciseTrafficRec{})
			// FIXME: capture analyzer should be able to reassemble the
			// fragments
			// verifyNonAppMeasurement(f, ms, layers.IPProtocolUDP)
		})
		// TODO: verify 'too large' error w/o setsockopt
	})
}

var _ = ginkgo.Describe("GTP Proxy", func() {
	describeGTPProxy("[IPv4]", framework.UPGIPModeV4)
	describeGTPProxy("[IPv6]", framework.UPGIPModeV6)
})

func describeGTPProxy(title string, ipMode framework.UPGIPMode) {
	ginkgo.Context(title, func() {
		var seid pfcp.SEID
		f := framework.NewDefaultFramework(framework.UPGModeGTPProxy, ipMode)

		ginkgo.BeforeEach(func() {
			ginkgo.By("starting a PFCP session")
			cfg := &framework.SessionConfig{
				IdBase:          1,
				UEIP:            f.UEIP(),
				Mode:            framework.UPGModeGTPProxy,
				TEIDPGWs5u:      framework.TEIDPGWs5u,
				TEIDSGWs5u:      framework.TEIDSGWs5u,
				PGWIP:           f.VPPCfg.GetNamespaceAddress("core").IP,
				SGWIP:           f.VPPCfg.GetNamespaceAddress("access").IP,
				ProxyAccessTEID: framework.ProxyAccessTEID,
				ProxyCoreTEID:   framework.ProxyCoreTEID,
				ProxyAccessIP:   f.VPPCfg.GetVPPAddress("access").IP,
				ProxyCoreIP:     f.VPPCfg.GetVPPAddress("core").IP,
				// Make sure PFCP_CLASSIFY is not set for the session.
				// That's an important edge case
				SkipSDFFilter: true,
			}
			var err error
			seid, err = f.PFCP.EstablishSession(f.Context, 0, cfg.SessionIEs()...)
			framework.ExpectNoError(err)
		})

		shouldPassTheTraffic := func() {
			runTrafficGen(f, smallVolumeHTTPConfig(nil), &traffic.PreciseTrafficRec{})
			deleteSession(f, seid, true)
		}

		ginkgo.It("should pass the traffic", shouldPassTheTraffic)

		ginkgo.Context("[GTP-U extensions]", func() {
			f.TPDUHook = func(tpdu *gtpumessage.TPDU, fromPGW bool) {
				defer ginkgo.GinkgoRecover()
				prepend := []byte{
					0,    // seq number hi (unused)
					0,    // seq number lo (unused)
					0,    // N-PDU number (unused)
					0x32, // next extension type
					1,    // ext header length
					0xaa, // ext content
					0xbb, // ext content
					0,    // next ext type: no extension
				}
				switch tpdu.TEID() {
				case framework.ProxyAccessTEID:
					// add an extension on the way towards the GTP proxy
					tpdu.Header.Flags |= 4
					tpdu.Payload = append(prepend, tpdu.Payload...)
				case framework.TEIDPGWs5u:
					// ext flag must still be set on the packets going towards
					// the PGW, after the proxy
					framework.ExpectEqual((tpdu.Header.Flags>>2)&1, uint8(1))
					// FIXME: fix go-gtp, the extension shouldn't be a part of the payload
					gomega.Expect(len(tpdu.Payload)).To(gomega.BeNumerically(">", len(prepend)))
					framework.ExpectEqual(tpdu.Payload[:len(prepend)], prepend)
					// remove the extension as go-gtp can't parse it atm
					tpdu.Header.Flags &^= 4
					tpdu.Payload = tpdu.Payload[len(prepend):]
					tpdu.SetLength()
				}
			}

			ginkgo.It("should pass the extensions as-is", shouldPassTheTraffic)
		})
	})
}

func describeNAT(f *framework.Framework) {
	ginkgo.Describe("NAT translations", func() {
		ginkgo.BeforeEach(func() {
			setupNAT(f)
		})

		verify := func(sessionCfg framework.SessionConfig) {
			sessionCfg.NatPoolName = "testing"
			seid := startMeasurementSession(f, &sessionCfg)
			trafficCfg := smallVolumeHTTPConfig(nil)
			trafficRec := &traffic.PreciseTrafficRec{}
			runTrafficGen(f, trafficCfg, trafficRec)
			foundAddr := trafficRec.ClientAddr()
			gomega.Expect(foundAddr).To(gomega.BeEquivalentTo("144.0.0.20:10128"))
			runTrafficGen(f, trafficCfg, trafficRec)
			foundAddr = trafficRec.ClientAddr()
			gomega.Expect(foundAddr).NotTo(gomega.BeEquivalentTo("144.0.0.30:55555"))
			deleteSession(f, seid, true)
		}

		ginkgo.It("applies to the non-proxied traffic", func() {
			verify(framework.SessionConfig{})
		})

		ginkgo.It("applies to the proxied traffic", func() {
			verify(framework.SessionConfig{AppName: "TST"})
		})
	})
}

func describeRoutingPolicy(f *framework.Framework) {
	ginkgo.Describe("routing policy", func() {
		var altServerIP *net.IPNet
		var ipTable uint32
		ginkgo.BeforeEach(func() {
			f.VPP.Ctl("ip table add 201")
			f.VPP.Ctl("ip6 table add 301")
			f.VPP.Ctl("upf policy add id altIP via ip4-lookup-in-table 201 via ip6-lookup-in-table 301")

			if f.IPMode == framework.UPGIPModeV4 {
				altServerIP = framework.MustParseIPNet("192.168.99.3/32")
				ipTable = 201
			} else {
				altServerIP = framework.MustParseIPNet("2001:db8:aa::3/128")
				ipTable = 301
			}
			f.AddCustomServerIP(altServerIP)
			f.VPP.Ctl("ip route add %s table %d via %s sgi0", altServerIP, ipTable, f.ServerIP())
		})

		verify := func(sessionCfg framework.SessionConfig) {
			sessionCfg.ForwardingPolicyID = "altIP"
			seid := startMeasurementSession(f, &sessionCfg)
			trafficCfg := smallVolumeHTTPConfig(nil)
			trafficCfg.AddServerIP(altServerIP.IP)
			runTrafficGen(f, trafficCfg, &traffic.PreciseTrafficRec{})
			ms := deleteSession(f, seid, true)
			verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, altServerIP.IP)
		}

		ginkgo.It("applies to the non-proxied traffic", func() {
			verify(framework.SessionConfig{})
		})

		ginkgo.It("applies to the proxied traffic", func() {
			verify(framework.SessionConfig{AppName: "TST"})
		})
	})
}

type measurementCfg struct {
	appPDR       bool
	fakeHostname bool
	redirect     bool
}

func startMeasurementSession(f *framework.Framework, cfg *framework.SessionConfig) pfcp.SEID {
	ginkgo.By("starting a PFCP session")
	cfg.IdBase = 1
	cfg.UEIP = f.UEIP()
	cfg.Mode = f.Mode
	if cfg.Mode == framework.UPGModePGW {
		cfg.TEIDPGWs5u = framework.TEIDPGWs5u
		cfg.TEIDSGWs5u = framework.TEIDSGWs5u
		cfg.PGWIP = f.VPPCfg.GetVPPAddress("grx").IP
		cfg.SGWIP = f.VPPCfg.GetNamespaceAddress("grx").IP
	}
	seid, err := f.PFCP.EstablishSession(f.Context, 0, cfg.SessionIEs()...)
	framework.ExpectNoError(err)
	return seid
}

func deleteSession(f *framework.Framework, seid pfcp.SEID, showInfo bool) *pfcp.PFCPMeasurement {
	if showInfo {
		f.VPP.Ctl("show upf session")
		f.VPP.Ctl("show upf flows")
	}

	ms, err := f.PFCP.DeleteSession(f.Context, seid)
	framework.ExpectNoError(err)
	return ms
}

func deleteSessions(f *framework.Framework, seids []pfcp.SEID, showInfo bool) []*pfcp.PFCPMeasurement {
	if showInfo {
		f.VPP.Ctl("show upf session")
		f.VPP.Ctl("show upf flows")
	}

	specs := make([]pfcp.SessionOpSpec, len(seids))
	for n, seid := range seids {
		specs[n].SEID = seid
	}

	ms, errs := f.PFCP.DeleteSessions(f.Context, specs)
	for _, err := range errs {
		framework.ExpectNoError(err)
	}
	return ms
}

func newTrafficGen(f *framework.Framework, cfg traffic.TrafficConfig, rec traffic.TrafficRec) (*traffic.TrafficGen, *network.NetNS, *network.NetNS) {
	ginkgo.By("starting the traffic generator")
	cfg.SetNoLinger(true)
	if !cfg.HasServerIP() {
		cfg.AddServerIP(f.ServerIP())
	}
	httpCfg, ok := cfg.(*traffic.HTTPConfig)
	if ok {
		// Avoid broken connections due to 5-tuple reuse
		// by using multiple server IPs
		// Perhaps flowtable should handle these situations better
		for i := 1; i < httpCfg.SimultaneousCount/10; i++ {
			cfg.AddServerIP(f.AddServerIP())
		}
	}
	clientNS := f.VPP.GetNS("ue")
	var serverNS *network.NetNS
	if f.Mode == framework.UPGModeGTPProxy {
		serverNS = f.VPP.GetNS("srv")
	} else {
		serverNS = f.VPP.GetNS("sgi")
	}
	return traffic.NewTrafficGen(cfg, rec), clientNS, serverNS
}

func runTrafficGen(f *framework.Framework, cfg traffic.TrafficConfig, rec traffic.TrafficRec) {
	tg, clientNS, serverNS := newTrafficGen(f, cfg, rec)
	framework.ExpectNoError(tg.Run(f.Context, clientNS, serverNS))
}

func verifyConnFlood(f *framework.Framework, netem bool) {
	rec := &traffic.SimpleTrafficRec{}
	tg, clientNS, serverNS := newTrafficGen(f, &traffic.HTTPConfig{
		Retry:             true,
		SimultaneousCount: 400, // TODO: 5000 works with bigger chunks but takes up too much memory
		Persist:           true,
		ChunkDelay:        -1,  // no delay
		ChunkSize:         100, // use small chunks to avoid using up too much memory
		ChunkCount:        1000,
	}, rec)

	ueLink := "access"
	if f.Mode == framework.UPGModeTDF {
		ueLink = "access0" // FIXME
	}

	if netem {
		framework.ExpectNoError(clientNS.SetNetem(ueLink, network.NetemAttrs{
			// TODO: different numbers
			Latency:   500000,
			Loss:      30,
			Duplicate: 10,
		}))
	}

	ctx, cancel := context.WithCancel(f.Context)
	defer cancel()
	tgDone := tg.Start(ctx, clientNS, serverNS)
	select {
	case <-f.Context.Done():
		// FIXME (this always gives an error, just fail)
		framework.ExpectNoError(f.Context.Err())
	case err := <-tgDone:
		// FIXME (this always gives an error, just fail)
		framework.ExpectNoError(err)
	case <-time.After(40 * time.Second):
		// TODO: FIXME: make sure it indeed does dowload something
		// framework.ExpectNoError(rec.Verify())
	}
	cancel()

	if netem {
		found, err := clientNS.DelNetem(ueLink)
		framework.ExpectNoError(err)
		gomega.Expect(found).To(gomega.BeTrue())
	}

	// make sure UPG and the session are still alive after the stress test
	rec = &traffic.SimpleTrafficRec{}
	tg, clientNS, serverNS = newTrafficGen(f, &traffic.UDPPingConfig{
		PacketCount: 3,
		Retry:       true,
	}, rec)
	framework.ExpectNoError(tg.Run(f.Context, clientNS, serverNS))
}

func verifySessionDeletionLoop(f *framework.Framework, seid *pfcp.SEID) {
	rec := &traffic.SimpleTrafficRec{}
	tg, clientNS, serverNS := newTrafficGen(f, &traffic.HTTPConfig{
		Retry:             true,
		SimultaneousCount: 400, // TODO: 5000 works with bigger chunks but takes up too much memory
		Persist:           true,
		ChunkDelay:        -1,  // no delay
		ChunkSize:         100, // use small chunks to avoid using up too much memory
		ChunkCount:        1000,
	}, rec)

	ctx, cancel := context.WithCancel(f.Context)
	defer cancel()

	tgDone := tg.Start(ctx, clientNS, serverNS)
LOOP:
	for {
		select {
		case <-time.After(5 * time.Second):
			if *seid == 0 {
				*seid = startMeasurementSession(f, &framework.SessionConfig{})
			} else {
				deleteSession(f, *seid, false)
				*seid = 0
			}
		case <-f.Context.Done():
			// FIXME (this always gives an error, just fail)
			framework.ExpectNoError(f.Context.Err())
		case <-tgDone:
			// don't fail, many failures during download are expected
			break LOOP
		case <-time.After(40 * time.Second):
			// don't fail, many failures during download are expected
			break LOOP
		}
	}

	if *seid == 0 {
		*seid = startMeasurementSession(f, &framework.SessionConfig{})
	}
	// make sure UPG and the session are still alive after the stress test
	rec = &traffic.SimpleTrafficRec{}
	tg, clientNS, serverNS = newTrafficGen(f, &traffic.UDPPingConfig{
		PacketCount: 3,
		Retry:       true,
	}, rec)
	framework.ExpectNoError(tg.Run(f.Context, clientNS, serverNS))
}

func startTrafficGen(f *framework.Framework, cfg traffic.TrafficConfig, rec traffic.TrafficRec) chan error {
	tg, clientNS, serverNS := newTrafficGen(f, cfg, rec)
	return tg.Start(f.Context, clientNS, serverNS)
}

func verifyAppMeasurement(f *framework.Framework, ms *pfcp.PFCPMeasurement, proto layers.IPProtocol, serverIP net.IP) {
	gomega.Expect(ms).NotTo(gomega.BeNil())

	verifyPreAppReport(ms, 1, NON_APP_TRAFFIC_THRESHOLD)
	validateReport(ms, 2)
	// [0] is b/c we're expecting just one report per URR ID here.
	// No split reports, which are handled by separate tests that
	// check Monitoring Time
	*ms.Reports[2][0].UplinkVolume += *ms.Reports[1][0].UplinkVolume
	*ms.Reports[2][0].DownlinkVolume += *ms.Reports[1][0].DownlinkVolume
	*ms.Reports[2][0].TotalVolume += *ms.Reports[1][0].TotalVolume
	verifyMainReport(f, ms, proto, 2, serverIP)
}

func verifyNonAppMeasurement(f *framework.Framework, ms *pfcp.PFCPMeasurement, proto layers.IPProtocol, serverIP net.IP) {
	verifyMainReport(f, ms, proto, 1, serverIP)
}

func validateReport(ms *pfcp.PFCPMeasurement, urrId uint32) pfcp.PFCPReport {
	framework.ExpectHaveKey(ms.Reports, urrId, "missing URR id: %d", urrId)
	gomega.Expect(ms.Reports[urrId]).To(gomega.HaveLen(1), "unexpected split report")
	r := ms.Reports[urrId][0]
	gomega.Expect(r.DownlinkVolume).ToNot(gomega.BeNil(), "downlink volume missing in the UsageReport")
	gomega.Expect(r.UplinkVolume).ToNot(gomega.BeNil(), "uplink volume missing in the UsageReport")
	gomega.Expect(r.TotalVolume).ToNot(gomega.BeNil(), "total volume missing in the UsageReport")
	framework.ExpectEqual(*r.UplinkVolume+*r.DownlinkVolume, *r.TotalVolume, "bad total volume")
	return r
}

func verifyPreAppReport(ms *pfcp.PFCPMeasurement, urrId uint32, toleration uint64) {
	r := validateReport(ms, urrId)
	gomega.Expect(*r.DownlinkVolume).To(gomega.BeNumerically("<=", toleration),
		"too much non-app dl traffic: %d (max %d)", *r.DownlinkVolume, toleration)
	gomega.Expect(*r.UplinkVolume).To(gomega.BeNumerically("<=", toleration),
		"too much non-app ul traffic: %d (max %d)", *r.DownlinkVolume, toleration)
}

func finalizeUECapture(f *framework.Framework) *network.Capture {
	var c *network.Capture
	if f.SlowGTPU() {
		// NOTE: if we use UE, we can get bad traffic figures,
		// as some packets could be lost due to GTPU
		// encap/decap being slow (especially true for the
		// userspace GTPU mode), so UPG sees them but UE
		// doesn't
		c = f.VPP.Captures["grx"]
	} else {
		// In TDF mode, UE netns is connected directly to the
		// VPP nents through a veth, so no loss is expected
		// there.
		// And kernel-based GTPU is just fast enough.
		c = f.VPP.Captures["ue"]
	}

	if c == nil {
		panic("capture not found")
	}

	// make sure the capture is finished, grabbing all of the late packets
	c.Stop()

	return c
}

func getTrafficCountsFromCapture(f *framework.Framework, proto layers.IPProtocol, serverIP net.IP) (ul, dl uint64) {
	c := finalizeUECapture(f)
	if serverIP == nil {
		serverIP = f.ServerIP()
	}
	ul = c.GetTrafficCount(network.Make5Tuple(f.UEIP(), -1, serverIP, -1, proto))
	dl = c.GetTrafficCount(network.Make5Tuple(serverIP, -1, f.UEIP(), -1, proto))
	framework.Logf("capture stats: UL: %d, DL: %d", ul, dl)
	return ul, dl
}

func getL4TrafficCountsFromCapture(f *framework.Framework, proto layers.IPProtocol, serverIP net.IP) (ul, dl uint64) {
	c := finalizeUECapture(f)
	if serverIP == nil {
		serverIP = f.ServerIP()
	}
	ul = c.GetL4TrafficCount(network.Make5Tuple(f.UEIP(), -1, serverIP, -1, proto))
	dl = c.GetL4TrafficCount(network.Make5Tuple(serverIP, -1, f.UEIP(), -1, proto))
	framework.Logf("l4 capture stats: UL: %d, DL: %d", ul, dl)
	return ul, dl
}

func verifyMainReport(f *framework.Framework, ms *pfcp.PFCPMeasurement, proto layers.IPProtocol, urrId uint32, serverIP net.IP) {
	ul, dl := getTrafficCountsFromCapture(f, proto, serverIP)
	r := validateReport(ms, urrId)
	framework.ExpectEqual(*r.UplinkVolume, ul, "uplink volume for urr %d", urrId)
	framework.ExpectEqual(*r.DownlinkVolume, dl, "downlink volume for urr %d", urrId)
}

func smallVolumeHTTPConfig(base *traffic.HTTPConfig) *traffic.HTTPConfig {
	if base == nil {
		base = &traffic.HTTPConfig{}
	}

	base.ChunkSize = 1000

	return base
}

// "UP F-SEID: 0xb2f982ab509feeb7 (12896482680255803063) @ 10.0.0.2"
var seidRx = regexp.MustCompile(`UP\s+F-SEID:\s+0x([0-9A-Fa-f]+)\s+`)

func verifyActiveSessions(f *framework.Framework, expectedSEIDs []pfcp.SEID) {
	// TODO: should be able to verify this via the API
	var actualSEIDs []pfcp.SEID
	out, err := f.VPP.Ctl("show upf session")
	framework.ExpectNoError(err)
	for _, m := range seidRx.FindAllStringSubmatch(out, -1) {
		seid, err := strconv.ParseUint(m[1], 16, 64)
		framework.ExpectNoError(err)
		actualSEIDs = append(actualSEIDs, pfcp.SEID(seid))
	}
	sort.Slice(expectedSEIDs, func(i, j int) bool {
		return expectedSEIDs[i] < expectedSEIDs[j]
	})
	sort.Slice(actualSEIDs, func(i, j int) bool {
		return actualSEIDs[i] < actualSEIDs[j]
	})
	framework.ExpectEqual(actualSEIDs, expectedSEIDs, "active sessions")
}

func verifyNoSession(f *framework.Framework, seid pfcp.SEID) {
	_, err := f.PFCP.DeleteSession(f.Context, seid)
	framework.ExpectError(err)
	var serverErr *pfcp.PFCPServerError
	gomega.Expect(errors.As(err, &serverErr)).To(gomega.BeTrue())
	// // 3GPP TS 29.244 Clause 7.2.2.4.2: Conditions for Sending SEID=0 in PFCP Header
	// framework.ExpectEqual(serverErr.SEID, pfcp.SEID(0))
	framework.ExpectEqual(serverErr.Cause, ie.CauseSessionContextNotFound)
}

// verifyPSDBU verifies that the message is a Session Report Request
// with PSDBU (PFCP Session Deleted By the UP function) bit set and
// the report(s) it contains have TEBUR (Termination By UP function
// Report) bit set
func verifyPSDBU(m message.Message, numUsageReports int) {
	framework.ExpectEqual(m.MessageType(), message.MsgTypeSessionReportRequest)

	rr := m.(*message.SessionReportRequest)
	gomega.Expect(rr.ReportType).NotTo(gomega.BeNil())
	_, err := rr.ReportType.ReportType()
	framework.ExpectNoError(err)
	gomega.Expect(rr.ReportType.HasUPIR()).To(gomega.BeFalse())
	gomega.Expect(rr.ReportType.HasERIR()).To(gomega.BeFalse())
	gomega.Expect(rr.ReportType.HasUSAR()).To(gomega.BeTrue())
	gomega.Expect(rr.ReportType.HasDLDR()).To(gomega.BeFalse())

	gomega.Expect(rr.PFCPSRReqFlags).NotTo(gomega.BeNil())
	gomega.Expect(rr.PFCPSRReqFlags.HasPSDBU()).To(gomega.BeTrue())

	gomega.Expect(rr.UsageReport).To(gomega.HaveLen(numUsageReports))
	for _, ur := range rr.UsageReport {
		urt, err := ur.FindByType(ie.UsageReportTrigger)
		framework.ExpectNoError(err)
		gomega.Expect(len(urt.Payload)).To(gomega.BeNumerically(">=", 3))
		// FIXME: TEBUR bit is not being set for the split
		// reports, when these are generated as part of PSDBU
		// Session Report Request. This is not in complete
		// agreement with the spec (TS 29.244 clause 5.18.2)
		// which says all of the included reports must have
		// TEBUR bit
		if !urt.HasMONIT() {
			gomega.Expect(urt.Payload[2] & 2).NotTo(gomega.BeZero()) // TEBUR bit is set
		}
	}
}

func setupNAT(f *framework.Framework) {
	f.VPP.Ctl("nat44 plugin enable sessions 1000")
	f.VPP.Ctl("set interface nat44 out sgi0 output-feature")
	f.VPP.Ctl("upf nat pool 144.0.0.20 - 144.0.0.120 block_size 512 nwi sgi name testing min_port 10128")
	f.VPP.Ctl("nat44 controlled enable")
}

func verifyPFCPError(err error, cause uint8, seid pfcp.SEID, failedRuleID uint32, message string) {
	framework.Logf("Server error (expected to occur): %v", err)
	framework.ExpectError(err, "expected PFCP error")
	var serverErr *pfcp.PFCPServerError
	gomega.Expect(errors.As(err, &serverErr)).To(gomega.BeTrue())
	if seid != 0 {
		framework.ExpectEqual(seid, serverErr.SEID, "SEID")
	}
	framework.ExpectEqual(serverErr.Cause, cause, "Cause")
	if failedRuleID != 0 {
		framework.ExpectEqual(serverErr.FailedRuleID, failedRuleID, "FailedRuleID")
	}
	framework.ExpectEqual(serverErr.Message, message, "Message")
}
