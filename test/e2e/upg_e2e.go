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
	"context"
	"fmt"
	"git.fd.io/govpp.git/binapi/fib_types"
	"git.fd.io/govpp.git/binapi/ip_types"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/pkg/errors"
	gtpumessage "github.com/wmnsk/go-gtp/gtpv1/message"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/travelping/upg-vpp/test/e2e/framework"
	"github.com/travelping/upg-vpp/test/e2e/network"
	"github.com/travelping/upg-vpp/test/e2e/pfcp"
	"github.com/travelping/upg-vpp/test/e2e/traffic"
	"github.com/travelping/upg-vpp/test/e2e/upf"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

const (
	NON_APP_TRAFFIC_THRESHOLD = 1000
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
		// TODO: fix these test cases for IPv6
		if ipMode == framework.UPGIPModeV4 {
			describeMTU(mode, ipMode)
		}
	})
}

func describeMeasurement(f *framework.Framework) {
	ginkgo.Describe("session measurement", func() {
		var ms *pfcp.PFCPMeasurement
		var seid pfcp.SEID

		sessionContext := func(desc string, cfg framework.SessionConfig, body func()) {
			ginkgo.Context(desc, func() {
				ginkgo.BeforeEach(func() {
					seid = startMeasurementSession(f, &cfg)
				})

				body()
			})
		}

		verify := func(cfg traffic.TrafficConfig) {
			runTrafficGen(f, cfg, &traffic.PreciseTrafficRec{})
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
				f.VPP.Ctl("ping %s source host-sgi0 repeat 3", appServerIP)

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
					flowStr, err := f.VPP.Ctl("show upf flows")
					framework.ExpectNoError(err)
					gomega.Expect(flowStr).To(gomega.ContainSubstring("proxy 0"))
					gomega.Expect(flowStr).NotTo(gomega.ContainSubstring("proxy 1"))
				})

				ginkgo.It("should not prevent ADF from working (no app hit)", func() {
					verify(smallVolumeHTTPConfig(nil))
					verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP, nil)

					// the flow should be proxied
					flowStr, err := f.VPP.Ctl("show upf flows")
					framework.ExpectNoError(err)
					gomega.Expect(flowStr).NotTo(gomega.ContainSubstring("proxy 0"))
					gomega.Expect(flowStr).To(gomega.ContainSubstring("proxy 1"))
				})

				ginkgo.It("should not prevent ADF from working (app hit)", func() {
					verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
						UseFakeHostname: true,
					}))
					verifyAppMeasurement(f, ms, layers.IPProtocolTCP, nil)

					// the flow should be proxied
					flowStr, err := f.VPP.Ctl("show upf flows")
					framework.ExpectNoError(err)
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

var _ = ginkgo.Describe("Binapi", func() {
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
		ginkgo.It("adds, removes and lists the NWI", func() {
			nwi := &upf.UpfNwiAddDel{
				IP4TableID:  200,
				Name: "testing",
				Add:  1,
			}
			nwiReply := &upf.UpfNwiAddDelReply{}
			err := f.VPP.ApiChannel.SendRequest(nwi).ReceiveReply(nwiReply)
			gomega.Expect(err).To(gomega.BeNil())

			reqCtx := f.VPP.ApiChannel.SendMultiRequest(&upf.UpfNwiDump{})
			var found bool
			for {
				msg := &upf.UpfNwiDetails{}
				stop, err := reqCtx.ReceiveReply(msg)
				gomega.Expect(err).To(gomega.BeNil())
				if stop {
					break
				}
				if msg.Name != "testing" {
					continue
				}
				found = true
			}
			gomega.Expect(found).To(gomega.BeTrue())

			nwi.Add = 0
			nwiReply = &upf.UpfNwiAddDelReply{}
			err = f.VPP.ApiChannel.SendRequest(nwi).ReceiveReply(nwiReply)
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
				if msg.Name != "testing" {
					continue
				}
				found = true
			}
			gomega.Expect(found).To(gomega.BeFalse())
		})
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
		f := framework.NewDefaultFramework(framework.UPGModeTDF, framework.UPGIPModeV4)
		f.PFCPCfg.IgnoreHeartbeatRequests = true
		ginkgo.It("should work correcty", func() {
			seids := []pfcp.SEID{
				startMeasurementSession(f, &framework.SessionConfig{}),
			}
			var wg sync.WaitGroup
			for i := 1; i <= 2; i++ {
				time.Sleep(50 * time.Millisecond)
				pfcpCfg := framework.DefaultPFCPConfig(*f.VPPCfg)
				pfcpCfg.Namespace = f.VPP.GetNS("cp")
				pfcpCfg.NodeID = fmt.Sprintf("node%d", i)
				pfcpCfg.CNodeIP = f.AddCNodeIP()
				// make UPG drop this association eventually
				pfcpCfg.IgnoreHeartbeatRequests = true
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
			}, &traffic.SimpleTrafficRec{})
			tg.Start(f.Context, clientNS, serverNS)

			ginkgo.By("Waiting for 1st monitoring time...")
			now := time.Now()
			gomega.Expect(now.Before(sessionCfg.MonitoringTime)).To(gomega.BeTrue())
			time.Sleep(sessionCfg.MonitoringTime.Add(2 * time.Second).Sub(now))

			ginkgo.By("Updating monitoring time in the session (1)")
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
						sessionCfgs[j].CreateFARs()...)
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
						sessionCfgs[j].CreateFARs()...)
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
					var serverErr *pfcp.PFCPServerError
					gomega.Expect(errors.As(err, &serverErr)).To(gomega.BeTrue())
					framework.ExpectEqual(newSEID, serverErr.SEID)
					framework.ExpectEqual(serverErr.Cause, ie.CauseRuleCreationModificationFailure)
					framework.Logf("Server error (expected): %v", err)
					// TODO: decode and verify TP error report
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
			framework.ExpectError(err)

			var serverErr *pfcp.PFCPServerError
			gomega.Expect(errors.As(err, &serverErr)).To(gomega.BeTrue())
			framework.ExpectEqual(newSEID, serverErr.SEID)
			framework.ExpectEqual(serverErr.Cause, ie.CauseRuleCreationModificationFailure)
			framework.Logf("Server error (expected): %v", err)

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
			framework.ExpectError(err)

			var serverErr *pfcp.PFCPServerError
			gomega.Expect(errors.As(err, &serverErr)).To(gomega.BeTrue())
			gomega.Expect(serverErr.SEID).To(gomega.Equal(seid))
			framework.ExpectEqual(serverErr.Cause, ie.CauseRequestRejected)
			framework.Logf("Server error (expected): %v", err)
			// TODO: decode and verify TP error report
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
			var serverErr *pfcp.PFCPServerError
			gomega.Expect(errors.As(err, &serverErr)).To(gomega.BeTrue())
			framework.ExpectEqual(serverErr.Cause, ie.CauseRuleCreationModificationFailure)

			sessionCfg.TEIDPGWs5u += 10
			seid1, err := f.PFCP.EstablishSession(f.Context, 0, sessionCfg.SessionIEs()...)
			framework.ExpectNoError(err)
			deleteSession(f, seid1, true)
		})
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
		ueLink = "access1" // FIXME
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

func getTrafficCountsFromCapture(f *framework.Framework, proto layers.IPProtocol, serverIP net.IP) (ul, dl uint64) {
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

	if serverIP == nil {
		serverIP = f.ServerIP()
	}
	ul = c.GetTrafficCount(network.Make5Tuple(f.UEIP(), -1, serverIP, -1, proto))
	dl = c.GetTrafficCount(network.Make5Tuple(serverIP, -1, f.UEIP(), -1, proto))
	framework.Logf("capture stats: UL: %d, DL: %d", ul, dl)
	return ul, dl
}

func verifyMainReport(f *framework.Framework, ms *pfcp.PFCPMeasurement, proto layers.IPProtocol, urrId uint32, serverIP net.IP) {
	ul, dl := getTrafficCountsFromCapture(f, proto, serverIP)
	r := validateReport(ms, urrId)
	framework.ExpectEqual(ul, *r.UplinkVolume, "uplink volume for urr %d", urrId)
	framework.ExpectEqual(dl, *r.DownlinkVolume, "downlink volume for urr %d", urrId)
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
