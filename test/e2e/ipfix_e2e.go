// ipfix_e2e.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2022 Travelping GmbH
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
	"net"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/travelping/upg-vpp/test/e2e/framework"
	"github.com/travelping/upg-vpp/test/e2e/pfcp"
	"github.com/travelping/upg-vpp/test/e2e/traffic"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

func describeIPFIX(title string, mode framework.UPGMode, ipMode framework.UPGIPMode) {
	ginkgo.Context(title+" [ipfix]", func() {
		ginkgo.Context("[FAR-based]", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}

			ginkgo.Context("'none' template", func() {
				v.withIPFIXHandler()

				ginkgo.It("doesn't send IPFIX reports", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						trafficCfg:  &traffic.UDPPingConfig{},
						protocol:    layers.IPProtocolUDP,
						noTemplates: true,
					})
					v.verifyNoRecs()
				})
			})

			ginkgo.Context("default template", func() {
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "default",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXDefaultRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [TCP] [proxy]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "default",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
						adf:                 true,
					})
					v.verifyIPFIXDefaultRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate: "default",
						trafficCfg: &traffic.UDPPingConfig{
							// have it span at several IPFIX reports
							PacketCount: 55,
							Delay:       210 * time.Millisecond,
						},
						protocol:            layers.IPProtocolUDP,
						expectedTrafficPort: 12345,
					})
					v.verifyIPFIXDefaultRecords()
				})

				ginkgo.It("doesn't recreate templates with different IDs unnecessarily", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "default",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXDefaultRecords()
					ids := v.ipfixHandler.getTemplateIDs()
					v.runSession(ipfixVerifierCfg{
						farTemplate:         "default",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					framework.ExpectEqual(v.ipfixHandler.getTemplateIDs(), ids,
						"registered template IDs")
				})
			})

			ginkgo.Context("dest template", func() {
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "dest",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXDestRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "dest",
						trafficCfg:          &traffic.UDPPingConfig{},
						protocol:            layers.IPProtocolUDP,
						expectedTrafficPort: 12345,
					})
					v.verifyIPFIXDestRecords()
				})

			})
		})

		ginkgo.Context("[NWI-based]", func() {
			tcpCfg := ipfixVerifierCfg{
				// NOTE: no farTemplate
				trafficCfg:          smallVolumeHTTPConfig(nil),
				protocol:            layers.IPProtocolTCP,
				expectedTrafficPort: 80,
			}
			udpCfg := ipfixVerifierCfg{
				trafficCfg:          &traffic.UDPPingConfig{},
				protocol:            layers.IPProtocolUDP,
				expectedTrafficPort: 12345,
			}

			ginkgo.Context("FAR override", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("default")
				// Templates 256 and 257 are expected early because IPFIX policy
				// is specified per NWI
				v.withIPFIXHandler()

				ginkgo.It("should take precedence over NWI", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate: "none",
						trafficCfg:  &traffic.UDPPingConfig{},
						protocol:    layers.IPProtocolUDP,
						noTemplates: true,
					})
					v.verifyNoRecs()
				})
			})

			ginkgo.Context("default template", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("default")
				// Templates 256 and 257 are expected early because IPFIX policy
				// is specified per NWI
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(tcpCfg)
					v.verifyIPFIXDefaultRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(udpCfg)
					v.verifyIPFIXDefaultRecords()
				})
			})

			ginkgo.Context("dest template", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("dest")
				// Templates 256 and 257 are expected early because IPFIX policy
				// is specified per NWI
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(tcpCfg)
					v.verifyIPFIXDestRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(udpCfg)
					v.verifyIPFIXDestRecords()
				})

			})
		})

		if ipMode == framework.UPGIPModeV4 && mode == framework.UPGModeTDF {
			ginkgo.Context("[NAT fields]", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("default")
				v.withIPFIXHandler()

				ginkgo.BeforeEach(func() {
					setupNAT(f)
				})

				ginkgo.It("includes NAT fields in IPFIX reports", func() {
					trafficCfg := smallVolumeHTTPConfig(nil)
					// Make sure the flow lasts long enough so that
					// we have start, end, and "in-between" IPFIX records
					// for it
					trafficCfg.ChunkCount = 40
					trafficCfg.ChunkDelay = 500 * time.Millisecond
					v.verifyIPFIX(ipfixVerifierCfg{
						trafficCfg:                  trafficCfg,
						protocol:                    layers.IPProtocolTCP,
						expectedTrafficPort:         80,
						natPoolName:                 "testing",
						postNATSourceIPv4Address:    framework.MustParseIP("144.0.0.20").To4(),
						postNAPTSourceTransportPort: 10128,
					})
					v.verifyIPFIXDefaultRecords()
					v.verifyNAT()
				})
			})
		}

		ginkgo.Context("[alt collector]", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}
			v.withExtraExporter()
			v.withAltCollector()
			v.withIPFIXHandler()

			ginkgo.It("sends IPFIX packets to the specified collector", func() {
				gomega.Expect(v.collectorIP).NotTo(gomega.BeNil())
				v.verifyIPFIX(ipfixVerifierCfg{
					// no farTemplate as NWI is configured
					// with IPFIX policy by withAltCollector()
					trafficCfg:          smallVolumeHTTPConfig(nil),
					protocol:            layers.IPProtocolTCP,
					expectedTrafficPort: 80,
				})
				v.verifyIPFIXDefaultRecords()
			})
		})

		ginkgo.Context("bad IPFIX collector spec for NWI", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}
			// no v.withExtraExporter() and thus
			// NWI is pointing to an unregistered collector IP
			v.withAltCollector()
			v.withIPFIXHandler()

			ginkgo.It("should be handled as no IPFIX exporter", func() {
				v.verifyIPFIX(ipfixVerifierCfg{
					trafficCfg:  &traffic.UDPPingConfig{},
					protocol:    layers.IPProtocolUDP,
					noTemplates: true,
				})
				v.verifyNoRecs()
			})
		})

		ginkgo.Context("[forwarding policy]", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}
			v.withForwardingPolicy("altIP")
			v.withNWIIPFIXPolicy("dest")
			v.withIPFIXHandler()
			ginkgo.It("records forwarding policy name in VRFname", func() {
				v.verifyIPFIX(ipfixVerifierCfg{
					trafficCfg:             smallVolumeHTTPConfig(nil),
					protocol:               layers.IPProtocolTCP,
					expectedTrafficPort:    80,
					forwardingPolicyID:     "altIP",
					expectedOriginVRFName:  "altIP",
					expectedReverseVRFName: "altIP",
				})
				v.verifyIPFIXDestRecords()
			})
		})

		ginkgo.Context("reporting interval", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}
			v.withNWIIPFIXPolicy("dest")
			v.withIPFIXHandler()
			v.withReportingInterval(7)
			ginkgo.It("can be set via NWI", func() {
				trafficCfg := smallVolumeHTTPConfig(nil)
				// Make sure the flow lasts long enough to measure the intervals
				trafficCfg.ChunkCount = 50
				trafficCfg.ChunkDelay = 500 * time.Millisecond
				v.verifyIPFIX(ipfixVerifierCfg{
					trafficCfg:          trafficCfg,
					protocol:            layers.IPProtocolTCP,
					expectedTrafficPort: 80,
				})
				v.verifyIPFIXDestRecords()
				v.verifyReportingInterval(7)
			})
		})
	})
}

type ipfixVerifierCfg struct {
	farTemplate                 string
	trafficCfg                  traffic.TrafficConfig
	expectedTrafficPort         uint16
	protocol                    layers.IPProtocol
	natPoolName                 string
	postNATSourceIPv4Address    net.IP
	postNAPTSourceTransportPort uint16
	adf                         bool
	forwardingPolicyID          string
	expectedOriginVRFName       string
	expectedReverseVRFName      string
	noTemplates                 bool
}

type ipfixVerifier struct {
	f            *framework.Framework
	ipfixHandler *ipfixHandler
	beginTS      time.Time
	ulStartTS    time.Time
	ulEndTS      time.Time
	dlStartTS    time.Time
	dlEndTS      time.Time
	seid         pfcp.SEID
	ms           *pfcp.PFCPMeasurement
	collectorIP  net.IP
	recs         []ipfixRecord
	cfg          ipfixVerifierCfg
	altServerIP  *net.IPNet
	fpIPTable    uint32
}

func (v *ipfixVerifier) modifySGi(callback func(nwiCfg *vpp.NWIConfig)) {
	for n := range v.f.VPPCfg.NWIs {
		nwiCfg := &v.f.VPPCfg.NWIs[n]
		if nwiCfg.Name == "sgi" {
			callback(nwiCfg)
		}
	}
}

func (v *ipfixVerifier) withForwardingPolicy(fpID string) {
	ginkgo.BeforeEach(func() {
		v.f.VPP.Ctl("ip table add 201")
		v.f.VPP.Ctl("ip6 table add 301")
		v.f.VPP.Ctl("upf policy add id %s via ip4-lookup-in-table 201 via ip6-lookup-in-table 301",
			fpID)
		if v.f.IPMode == framework.UPGIPModeV4 {
			v.altServerIP = framework.MustParseIPNet("192.168.99.3/32")
			v.fpIPTable = 201
		} else {
			v.altServerIP = framework.MustParseIPNet("2001:db8:aa::3/128")
			v.fpIPTable = 301
		}
		v.f.AddCustomServerIP(v.altServerIP)
		v.f.VPP.Ctl("ip route add %s table %d via %s host-sgi0",
			v.altServerIP, v.fpIPTable, v.f.ServerIP())
	})
}

func (v *ipfixVerifier) withIPFIXHandler() {
	v.modifySGi(func(nwiCfg *vpp.NWIConfig) {
		// always set observationDomain{Id/Name} / observationPointId
		// as these values are used when the ipfix policy is specified
		// via a FAR, too
		nwiCfg.ObservationDomainId = 42
		nwiCfg.ObservationDomainName = "test-domain"
		nwiCfg.ObservationPointId = 4242
	})

	ginkgo.BeforeEach(func() {
		// The default exporter can't be set via
		// ipfix_exporter_create_delete API call
		v.f.VPP.Ctl("set ipfix exporter collector %s src %s "+
			"template-interval 1 port %d path-mtu 1450",
			v.f.PFCPCfg.CNodeIP,
			v.f.PFCPCfg.UNodeIP,
			IPFIX_PORT,
		)
		v.ipfixHandler = setupIPFIX(v.f, v.collectorIP)
		v.beginTS = time.Now()
		v.ulStartTS = time.Time{}
		v.ulEndTS = v.beginTS
		v.dlStartTS = time.Time{}
		v.dlEndTS = v.beginTS
	})

	ginkgo.AfterEach(func() {
		defer v.ipfixHandler.stop()
		v.collectorIP = nil
	})
}

func (v *ipfixVerifier) withNWIIPFIXPolicy(name string) {
	v.modifySGi(func(nwiCfg *vpp.NWIConfig) {
		nwiCfg.IPFIXPolicy = name
	})
}

func (v *ipfixVerifier) withReportingInterval(seconds int) {
	v.modifySGi(func(nwiCfg *vpp.NWIConfig) {
		nwiCfg.IPFIXReportingInterval = seconds
	})
}

func (v *ipfixVerifier) getCollectorIP() net.IP {
	if v.collectorIP == nil {
		v.collectorIP = v.f.AddCNodeIP()
	}
	return v.collectorIP
}

func (v *ipfixVerifier) withExtraExporter() {
	v.f.VPPCfg.IPFIXExporters = append(v.f.VPPCfg.IPFIXExporters,
		vpp.IPFIXExporterConfig{
			GetCollectorIP: v.getCollectorIP,
			GetSrcIP: func() net.IP {
				return v.f.PFCPCfg.UNodeIP
			},
			Port: IPFIX_PORT,
			VRF:  0,
		})
}

func (v *ipfixVerifier) withAltCollector() {
	v.modifySGi(func(nwiCfg *vpp.NWIConfig) {
		nwiCfg.IPFIXPolicy = "default"
		nwiCfg.GetIPFIXCollectorIP = v.getCollectorIP
	})
}

func (v *ipfixVerifier) runSession(cfg ipfixVerifierCfg) {
	v.cfg = cfg
	appName := ""
	if cfg.adf {
		appName = framework.HTTPAppName
	}
	v.seid = startMeasurementSession(v.f, &framework.SessionConfig{
		IMSI:               "313460000000001",
		IPFIXTemplate:      cfg.farTemplate,
		NatPoolName:        cfg.natPoolName,
		AppName:            appName,
		ForwardingPolicyID: cfg.forwardingPolicyID,
	})
	sessionStr, err := v.f.VPP.Ctl("show upf session")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(sessionStr).To(gomega.ContainSubstring("313460000000001"))
	if cfg.forwardingPolicyID != "" {
		cfg.trafficCfg.AddServerIP(v.altServerIP.IP)
	}
	runTrafficGen(v.f, cfg.trafficCfg, &traffic.PreciseTrafficRec{})
	if !v.cfg.noTemplates {
		gomega.Eventually(v.ipfixHandler.getTemplateIDs, 10*time.Second, time.Second).
			ShouldNot(gomega.BeEmpty())
	}
	v.ms = deleteSession(v.f, v.seid, true)
	// Wait a bit for all the reports to arrive
	// FIXME: actually, we should check IPFIX report results
	// via Eventually(), but that's a bit too much trouble for now,
	// so let's just do time.Sleep()
	time.Sleep(2 * time.Second)
}

func (v *ipfixVerifier) verifyIPFIX(cfg ipfixVerifierCfg) {
	v.runSession(cfg)

	var serverIP net.IP
	if v.altServerIP != nil {
		serverIP = v.altServerIP.IP
	}
	verifyNonAppMeasurement(v.f, v.ms, cfg.protocol, serverIP)

	v.recs = v.ipfixHandler.getRecords()
}

func (v *ipfixVerifier) verifyNoRecs() {
	gomega.Expect(v.recs).To(gomega.BeEmpty())
}

func (v *ipfixVerifier) verifyIPFIXStart() {
	// make sure the first report is not sent out immediately
	t := v.ipfixHandler.getFirstReportTS().Sub(v.beginTS)
	gomega.Expect(t.Seconds()).To(gomega.BeNumerically(">=", 2))
}

func (v *ipfixVerifier) verifyNAT() {
	gomega.Expect(len(v.recs)).To(gomega.BeNumerically(">", 2))
	// 1st IPFIX record for the flow, NAT44 session create
	framework.ExpectEqual(v.recs[0]["natEvent"], uint8(4))
	last := len(v.recs) - 1
	// last IPFIX record for the flow NAT44 session delete
	framework.ExpectEqual(v.recs[last]["natEvent"], uint8(5))
	// other records have 0 as natEvent (reserved, no event)
	for _, r := range v.recs[1:last] {
		framework.ExpectEqual(r["natEvent"], uint8(0))
	}
}

func (v *ipfixVerifier) verifyIPFIXDefaultRecords() {
	v.verifyIPFIXStart()
	// total counts not used for now, but kept here in case if they're needed later
	var ulPacketCount, dlPacketCount, ulOctets, dlOctets uint64
	// var initiatorPackets, responderPackets uint64
	// var initiatorOctets, responderOctets uint64
	var clientPort uint16
	for _, r := range v.recs {
		// The record looks like:
		// mobileIMSI: 313460000000001
		// packetTotalCount: 80
		// flowStartNanoseconds: 2022-02-22 02:30:32.097219204 +0000 UTC
		// flowEndNanoseconds: 2022-02-22 02:30:47.152832735 +0000 UTC
		// sourceIPv4Address: 10.1.0.3
		// destinationIPv4Address: 10.0.1.3
		// protocolIdentifier: 6
		// octetTotalCount: 4262
		// sourceTransportPort: 36960
		// destinationTransportPort: 80
		gomega.Expect(r).To(gomega.HaveKeyWithValue("mobileIMSI", "313460000000001"))
		// gomega.Expect(r).To(gomega.HaveKey("packetTotalCount"))
		gomega.Expect(r).To(gomega.HaveKey("flowStartNanoseconds"))
		gomega.Expect(r).To(gomega.HaveKey("flowEndNanoseconds"))
		gomega.Expect(r["flowEndNanoseconds"]).
			To(gomega.BeTemporally(">=", r["flowStartNanoseconds"].(time.Time)),
				"flowEndNanoseconds >= flowStartNanoseconds")
		gomega.Expect(r).To(gomega.HaveKeyWithValue("protocolIdentifier", uint8(v.cfg.protocol)))

		srcAddressKey := "sourceIPv4Address"
		dstAddressKey := "destinationIPv4Address"
		if v.f.IPMode == framework.UPGIPModeV6 {
			srcAddressKey = "sourceIPv6Address"
			dstAddressKey = "destinationIPv6Address"
		}
		gomega.Expect(r).To(gomega.HaveKey(srcAddressKey))
		gomega.Expect(r).To(gomega.HaveKey(dstAddressKey))

		// For now, we're using octetDeltaCount / packetDeltaCount
		// values instead of initator.../responder... fields.
		// Unlike initiator/responder, these depend on the
		// direction of the flow
		// gomega.Expect(r).To(gomega.HaveKey("initiatorPackets"))
		// gomega.Expect(r).To(gomega.HaveKey("responderPackets"))
		// gomega.Expect(r).To(gomega.HaveKey("initiatorOctets"))
		// gomega.Expect(r).To(gomega.HaveKey("responderOctets"))
		// initiatorPackets += r["initiatorPackets"].(uint64)
		// responderPackets += r["responderPackets"].(uint64)
		// initiatorOctets += r["initiatorOctets"].(uint64)
		// responderOctets += r["responderOctets"].(uint64)
		gomega.Expect(r).To(gomega.HaveKey("packetDeltaCount"))
		gomega.Expect(r).To(gomega.HaveKey("octetDeltaCount"))

		gomega.Expect(r).To(gomega.HaveKeyWithValue("observationDomainId", uint32(42)))

		if r[srcAddressKey].(net.IP).Equal(v.f.UEIP()) {
			// upload
			if v.ulStartTS.IsZero() {
				v.ulStartTS = r["flowStartNanoseconds"].(time.Time)
				// FIXME: should be working (wrong time on the VPP side?)
				// gomega.Expect(ulStartTS).To(gomega.BeTemporally(">=", beginTS))
			} else {
				gomega.Expect(r["flowStartNanoseconds"]).To(gomega.Equal(v.ulStartTS))
			}
			gomega.Expect(r["flowEndNanoseconds"]).To(gomega.BeTemporally(">", v.ulEndTS))
			v.ulEndTS = r["flowEndNanoseconds"].(time.Time)
			gomega.Expect(r[dstAddressKey].(net.IP).Equal(v.f.ServerIP())).To(gomega.BeTrue())
			// gomega.Expect(r["packetTotalCount"]).To(gomega.BeNumerically(">=", ulPacketCount))
			ulPacketCount += r["packetDeltaCount"].(uint64)
			// gomega.Expect(r["octetTotalCount"]).To(gomega.BeNumerically(">=", ulOctets))
			ulOctets += r["octetDeltaCount"].(uint64)
			gomega.Expect(r["destinationTransportPort"]).To(gomega.Equal(v.cfg.expectedTrafficPort))
			if clientPort == 0 {
				clientPort = r["sourceTransportPort"].(uint16)
			} else {
				gomega.Expect(r["sourceTransportPort"]).To(gomega.Equal(clientPort))
			}
			// gomega.Expect(r["flowDirection"]).To(gomega.Equal(uint8(1))) // egress flow
			if v.cfg.postNATSourceIPv4Address != nil {
				gomega.Expect(r["postNATSourceIPv4Address"]).
					To(gomega.Equal(v.cfg.postNATSourceIPv4Address))
			}
			if v.cfg.postNAPTSourceTransportPort != 0 {
				gomega.Expect(r["postNAPTSourceTransportPort"]).
					To(gomega.Equal(v.cfg.postNAPTSourceTransportPort))
			}
		} else {
			// download
			if v.dlStartTS.IsZero() {
				v.dlStartTS = r["flowStartNanoseconds"].(time.Time)
				// FIXME: should be working (wrong time on the VPP side?)
				// gomega.Expect(dlStartTS).To(gomega.BeTemporally(">=", beginTS))
			} else {
				gomega.Expect(r["flowStartNanoseconds"]).To(gomega.Equal(v.dlStartTS))
			}
			gomega.Expect(r["flowEndNanoseconds"]).To(gomega.BeTemporally(">=", v.dlEndTS))
			v.dlEndTS = r["flowEndNanoseconds"].(time.Time)
			gomega.Expect(r[srcAddressKey].(net.IP).Equal(v.f.ServerIP())).To(gomega.BeTrue())
			gomega.Expect(r[dstAddressKey].(net.IP).Equal(v.f.UEIP())).To(gomega.BeTrue())
			// gomega.Expect(r["packetTotalCount"]).To(gomega.BeNumerically(">=", dlPacketCount))
			dlPacketCount += r["packetDeltaCount"].(uint64)
			// gomega.Expect(r["octetTotalCount"]).To(gomega.BeNumerically(">=", dlOctets))
			dlOctets += r["octetDeltaCount"].(uint64)
			gomega.Expect(r["sourceTransportPort"]).To(gomega.Equal(v.cfg.expectedTrafficPort))
			if clientPort == 0 {
				clientPort = r["destinationTransportPort"].(uint16)
			} else {
				gomega.Expect(r["destinationTransportPort"]).To(gomega.Equal(clientPort))
			}
			// gomega.Expect(r["flowDirection"]).To(gomega.Equal(uint8(0))) // ingress flow
		}
	}

	gomega.Expect(ulPacketCount).To(gomega.Equal(*v.ms.Reports[1][0].UplinkPacketCount), "uplink packet count")
	gomega.Expect(dlPacketCount).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkPacketCount), "downlink packet count")
	// gomega.Expect(initiatorPackets).To(gomega.Equal(*v.ms.Reports[1][0].UplinkPacketCount), "initiatorPackets")
	// gomega.Expect(responderPackets).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkPacketCount), "responderPackets")
	gomega.Expect(ulOctets).To(gomega.Equal(*v.ms.Reports[1][0].UplinkVolume), "uplink volume")
	gomega.Expect(dlOctets).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkVolume), "downlink volume")

	// l4UL, l4DL := getL4TrafficCountsFromCapture(v.f, v.cfg.protocol, nil)
	// gomega.Expect(initiatorOctets).To(gomega.Equal(l4UL), "initiatorOctets")
	// gomega.Expect(responderOctets).To(gomega.Equal(l4DL), "responderOctets")
}

func (v *ipfixVerifier) verifyIPFIXDestRecords() {
	v.verifyIPFIXStart()
	// total counts not used for now, but kept here in case if they're needed later
	var ulOctets, dlOctets uint64
	// var initiatorOctets, responderOctets uint64
	for _, r := range v.recs {
		gomega.Expect(r).To(gomega.HaveKey("flowEndNanoseconds"))

		srcAddressKey := "sourceIPv4Address"
		dstAddressKey := "destinationIPv4Address"
		if v.f.IPMode == framework.UPGIPModeV6 {
			srcAddressKey = "sourceIPv6Address"
			dstAddressKey = "destinationIPv6Address"
		}
		gomega.Expect(r).To(gomega.HaveKey(srcAddressKey))
		gomega.Expect(r).To(gomega.HaveKey(dstAddressKey))
		gomega.Expect(r).To(gomega.HaveKey("flowDirection"))
		// For now, we're using octetDeltaCount
		// values instead of initator.../responder... fields.
		// Unlike initiator/responder, these depend on the
		// direction of the flow
		// gomega.Expect(r).To(gomega.HaveKey("initiatorOctets"))
		// gomega.Expect(r).To(gomega.HaveKey("responderOctets"))
		// initiatorOctets += r["initiatorOctets"].(uint64)
		// responderOctets += r["responderOctets"].(uint64)
		gomega.Expect(r).To(gomega.HaveKey("octetDeltaCount"))
		gomega.Expect(r).To(gomega.HaveKey("ingressVRFID"))
		gomega.Expect(r).To(gomega.HaveKey("egressVRFID"))
		originVRFName := "ipv4-VRF:200"
		reverseVRFName := "ipv4-VRF:100"
		if v.f.IPMode == framework.UPGIPModeV6 {
			originVRFName = "ipv6-VRF:200"
			reverseVRFName = "ipv6-VRF:100"
		}
		if v.cfg.expectedOriginVRFName != "" {
			originVRFName = v.cfg.expectedOriginVRFName
		}
		if v.cfg.expectedReverseVRFName != "" {
			reverseVRFName = v.cfg.expectedReverseVRFName
		}

		gomega.Expect(r).To(gomega.HaveKey("interfaceName"))
		gomega.Expect(r).To(gomega.HaveKeyWithValue("observationDomainId", uint32(42)))
		gomega.Expect(r).To(gomega.HaveKeyWithValue("observationDomainName", "test-domain"))
		gomega.Expect(r).To(gomega.HaveKeyWithValue("observationPointId", uint64(4242)))

		if r[srcAddressKey].(net.IP).Equal(v.f.UEIP()) {
			// upload
			gomega.Expect(r["flowEndNanoseconds"]).To(gomega.BeTemporally(">", v.ulEndTS))
			v.ulEndTS = r["flowEndNanoseconds"].(time.Time)
			expectedEgressVRFID := uint32(200)
			serverIP := v.f.ServerIP()
			if v.altServerIP != nil {
				serverIP = v.altServerIP.IP
				expectedEgressVRFID = 201
				if v.f.IPMode == framework.UPGIPModeV6 {
					expectedEgressVRFID = 301
				}
			}
			gomega.Expect(r[dstAddressKey].(net.IP).Equal(serverIP)).To(gomega.BeTrue())
			gomega.Expect(r["flowDirection"]).To(gomega.Equal(uint8(1))) // egress flow
			gomega.Expect(r["ingressVRFID"]).To(gomega.Equal(uint32(100)))
			gomega.Expect(r["egressVRFID"]).To(gomega.Equal(expectedEgressVRFID))
			gomega.Expect(r["VRFname"]).To(gomega.Equal(originVRFName))
			gomega.Expect(r["interfaceName"]).To(gomega.Equal("host-sgi0"))
			ulOctets += r["octetDeltaCount"].(uint64)
		} else {
			// download
			gomega.Expect(r["flowEndNanoseconds"]).To(gomega.BeTemporally(">=", v.dlEndTS))
			v.dlEndTS = r["flowEndNanoseconds"].(time.Time)
			serverIP := v.f.ServerIP()
			if v.altServerIP != nil {
				serverIP = v.altServerIP.IP
			}
			gomega.Expect(r[srcAddressKey].(net.IP).Equal(serverIP)).To(gomega.BeTrue())
			gomega.Expect(r[dstAddressKey].(net.IP).Equal(v.f.UEIP())).To(gomega.BeTrue())
			gomega.Expect(r["flowDirection"]).To(gomega.Equal(uint8(0))) // ingress flow
			gomega.Expect(r["ingressVRFID"]).To(gomega.Equal(uint32(200)))
			gomega.Expect(r["egressVRFID"]).To(gomega.Equal(uint32(100)))
			gomega.Expect(r["VRFname"]).To(gomega.Equal(reverseVRFName))
			expectedIfName := "host-access0"
			if v.f.Mode == framework.UPGModePGW {
				expectedIfName = "host-grx0"
			}
			gomega.Expect(r["interfaceName"]).To(gomega.Equal(expectedIfName))
			dlOctets += r["octetDeltaCount"].(uint64)
		}
	}

	// l4UL, l4DL := getL4TrafficCountsFromCapture(v.f, v.cfg.protocol, nil)
	// gomega.Expect(initiatorOctets).To(gomega.Equal(l4UL), "initiatorOctets")
	// gomega.Expect(responderOctets).To(gomega.Equal(l4DL), "responderOctets")

	gomega.Expect(ulOctets).To(gomega.Equal(*v.ms.Reports[1][0].UplinkVolume), "uplink volume")
	gomega.Expect(dlOctets).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkVolume), "downlink volume")
}

func (v *ipfixVerifier) verifyReportingInterval(expectedSeconds int) {
	var ingressTimes, egressTimes []time.Time
	for _, r := range v.recs {
		dir := r["flowDirection"].(uint8)
		ts := r["ts"].(time.Time)
		if dir == 0 {
			ingressTimes = append(ingressTimes, ts)
		} else {
			framework.ExpectEqual(dir, uint8(1))
			egressTimes = append(egressTimes, ts)
		}
	}
	atLeastMs := uint64(expectedSeconds) * 1000
	verifyIntervals(ingressTimes, atLeastMs)
	verifyIntervals(egressTimes, atLeastMs)
}

func verifyIntervals(times []time.Time, atLeastMs uint64) {
	gomega.Expect(len(times)).To(gomega.BeNumerically(">", 3))
	// the last interval may be shorter b/c the session is deleted
	for n := 1; n < len(times)-1; n++ {
		deltaT := times[n].Sub(times[n-1]).Milliseconds()
		gomega.Expect(deltaT).To(gomega.BeNumerically(">=", atLeastMs-500))
	}
}
