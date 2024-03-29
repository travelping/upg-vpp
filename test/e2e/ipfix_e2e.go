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

			ginkgo.Context("NatEvent template", func() {
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "NatEvent",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXNatEventRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [TCP] [proxy]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "NatEvent",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
						adf:                 true,
					})
					v.verifyIPFIXNatEventRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate: "NatEvent",
						trafficCfg: &traffic.UDPPingConfig{
							// have it span at several IPFIX reports
							PacketCount: 55,
							Delay:       210 * time.Millisecond,
						},
						protocol:            layers.IPProtocolUDP,
						expectedTrafficPort: 12345,
					})
					v.verifyIPFIXNatEventRecords()
				})

				ginkgo.It("doesn't recreate templates with different IDs unnecessarily", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "NatEvent",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXNatEventRecords()
					ids := v.ipfixHandler.getTemplateIDs()
					v.runSession(ipfixVerifierCfg{
						farTemplate:         "NatEvent",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					time.Sleep(2 * time.Second) // just in case wait for flushing and interval
					framework.ExpectEqual(v.ipfixHandler.getTemplateIDs(), ids,
						"registered template IDs")
				})
			})

			ginkgo.Context("FlowUsage template", func() {
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "FlowUsage",
						trafficCfg:          smallVolumeHTTPConfig(nil),
						protocol:            layers.IPProtocolTCP,
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXFlowUsageRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "FlowUsage",
						trafficCfg:          &traffic.UDPPingConfig{},
						protocol:            layers.IPProtocolUDP,
						expectedTrafficPort: 12345,
					})
					v.verifyIPFIXFlowUsageRecords()
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
				v.withNWIIPFIXPolicy("NatEvent")
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

			ginkgo.Context("NatEvent template", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("NatEvent")
				// Templates 256 and 257 are expected early because IPFIX policy
				// is specified per NWI
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(tcpCfg)
					v.verifyIPFIXNatEventRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(udpCfg)
					v.verifyIPFIXNatEventRecords()
				})
			})

			ginkgo.Context("FlowUsage template", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("FlowUsage")
				// Templates 256 and 257 are expected early because IPFIX policy
				// is specified per NWI
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(tcpCfg)
					v.verifyIPFIXFlowUsageRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(udpCfg)
					v.verifyIPFIXFlowUsageRecords()
				})

			})
		})

		if ipMode == framework.UPGIPModeV4 && mode == framework.UPGModeTDF {
			ginkgo.Context("[NAT fields]", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("NatEvent")
				v.withReportingInterval(5)
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
					v.verifyIPFIXNatEventRecords()
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
				v.verifyIPFIXNatEventRecords()
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
			v.withNWIIPFIXPolicy("FlowUsage")
			v.withIPFIXHandler()
			ginkgo.It("records forwarding policy name in VRFname", func() {
				v.verifyIPFIX(ipfixVerifierCfg{
					trafficCfg:            smallVolumeHTTPConfig(nil),
					protocol:              layers.IPProtocolTCP,
					expectedTrafficPort:   80,
					forwardingPolicyID:    "altIP",
					expectedUplinkVRFName: "altIP",
				})
				v.verifyIPFIXFlowUsageRecords()
			})
		})

		ginkgo.Context("reporting interval", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}
			v.withNWIIPFIXPolicy("FlowUsage")
			v.withIPFIXHandler()
			const INTERVAL = 3
			const MIN_REPORTS_FOR_CHECK = 5
			v.withReportingInterval(INTERVAL)
			ginkgo.It("can be set via NWI", func() {
				trafficCfg := smallVolumeHTTPConfig(nil)
				// Make sure the flow lasts long enough to measure the intervals
				trafficCfg.ChunkCount = MIN_REPORTS_FOR_CHECK * (INTERVAL + 1)
				trafficCfg.ChunkDelay = time.Second
				v.verifyIPFIX(ipfixVerifierCfg{
					trafficCfg:          trafficCfg,
					protocol:            layers.IPProtocolTCP,
					expectedTrafficPort: 80,
				})
				v.verifyIPFIXFlowUsageRecords()
				v.verifyReportingInterval(INTERVAL)
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
	expectedUplinkVRFName       string
	noTemplates                 bool
}

type ipfixVerifier struct {
	f            *framework.Framework
	ipfixHandler *ipfixHandler
	beginTS      time.Time
	startTS      time.Time
	endTS        time.Time
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
		v.f.VPP.Ctl("ip route add %s table %d via %s sgi0",
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
		v.startTS = time.Time{}
		v.endTS = v.beginTS
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
		nwiCfg.IPFIXPolicy = "NatEvent"
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

	if !cfg.noTemplates {
		// VPP ipfix plugin has loop which executes every 5 seconds,
		// only after at least once this loop iterates - new template interval will be used
		const VPP_IPFIX_TEMPLATE_REACTION_TIME = 20 * time.Second

		// After session creation vpp detects that far has template id
		// and should start broadcast corresponding template
		gomega.Eventually(v.ipfixHandler.getTemplateIDs, VPP_IPFIX_TEMPLATE_REACTION_TIME, time.Second).
			ShouldNot(gomega.BeEmpty())
	}

	runTrafficGen(v.f, cfg.trafficCfg, &traffic.PreciseTrafficRec{})

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

func (v *ipfixVerifier) verifyIPFIXSharedRecords() {
	var ulPacketCount, dlPacketCount, ulOctets, dlOctets uint64

	srcAddressKey := "sourceIPv4Address"
	dstAddressKey := "destinationIPv4Address"
	if v.f.IPMode == framework.UPGIPModeV6 {
		srcAddressKey = "sourceIPv6Address"
		dstAddressKey = "destinationIPv6Address"
	}

	serverIP := v.f.ServerIP()
	if v.altServerIP != nil {
		serverIP = v.altServerIP.IP
	}

	for _, r := range v.recs {
		gomega.Expect(r).To(gomega.HaveKeyWithValue("observationDomainId", uint32(42)))

		gomega.Expect(r).To(gomega.HaveKey("flowStartMilliseconds"))
		gomega.Expect(r).To(gomega.HaveKey("flowEndMilliseconds"))
		gomega.Expect(r["flowEndMilliseconds"]).
			To(gomega.BeTemporally(">=", r["flowStartMilliseconds"].(time.Time)),
				"flowEndMilliseconds >= flowStartMilliseconds")

		gomega.Expect(r).To(gomega.HaveKeyWithValue("protocolIdentifier", uint8(v.cfg.protocol)))

		gomega.Expect(r).To(gomega.HaveKey(srcAddressKey))
		gomega.Expect(r).To(gomega.HaveKey(dstAddressKey))

		gomega.Expect(r).To(gomega.HaveKey("initiatorPackets"))
		gomega.Expect(r).To(gomega.HaveKey("responderPackets"))
		gomega.Expect(r).To(gomega.HaveKey("initiatorOctets"))
		gomega.Expect(r).To(gomega.HaveKey("responderOctets"))

		if v.startTS.IsZero() {
			v.startTS = r["flowStartMilliseconds"].(time.Time)
			// FIXME: should be working (wrong time on the VPP side?)
			// gomega.Expect(ulStartTS).To(gomega.BeTemporally(">=", beginTS))
		} else {
			gomega.Expect(r["flowStartMilliseconds"]).To(gomega.Equal(v.startTS))
		}

		gomega.Expect(r["flowEndMilliseconds"]).To(gomega.BeTemporally(">=", v.endTS))
		v.endTS = r["flowEndMilliseconds"].(time.Time)

		// verify ips
		gomega.Expect(r[srcAddressKey].(net.IP).Equal(v.f.UEIP())).To(gomega.BeTrue())
		gomega.Expect(r[dstAddressKey].(net.IP).Equal(serverIP)).To(gomega.BeTrue())

		// collect stats
		ulPacketCount += r["initiatorPackets"].(uint64)
		ulOctets += r["initiatorOctets"].(uint64)
		dlPacketCount += r["responderPackets"].(uint64)
		dlOctets += r["responderOctets"].(uint64)
	}

	gomega.Expect(ulPacketCount).To(gomega.Equal(*v.ms.Reports[1][0].UplinkPacketCount), "uplink packet count")
	gomega.Expect(dlPacketCount).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkPacketCount), "downlink packet count")
	// gomega.Expect(initiatorPackets).To(gomega.Equal(*v.ms.Reports[1][0].UplinkPacketCount), "initiatorPackets")
	// gomega.Expect(responderPackets).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkPacketCount), "responderPackets")
	gomega.Expect(ulOctets).To(gomega.Equal(*v.ms.Reports[1][0].UplinkVolume), "uplink volume")
	gomega.Expect(dlOctets).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkVolume), "downlink volume")
}

func (v *ipfixVerifier) verifyIPFIXNatEventRecords() {
	var clientPort uint16

	for _, r := range v.recs {
		gomega.Expect(r).To(gomega.HaveKeyWithValue("mobileIMSI", "313460000000001"))

		gomega.Expect(r).To(gomega.HaveKey("initiatorPackets"))
		gomega.Expect(r).To(gomega.HaveKey("responderPackets"))
		gomega.Expect(r).To(gomega.HaveKey("initiatorOctets"))
		gomega.Expect(r).To(gomega.HaveKey("responderOctets"))

		// verify ports
		gomega.Expect(r["destinationTransportPort"]).To(gomega.Equal(v.cfg.expectedTrafficPort))
		if clientPort == 0 {
			clientPort = r["sourceTransportPort"].(uint16)
		} else {
			gomega.Expect(r["sourceTransportPort"]).To(gomega.Equal(clientPort))
		}

		// verify nat
		if v.cfg.postNATSourceIPv4Address != nil {
			gomega.Expect(r["postNATSourceIPv4Address"]).
				To(gomega.Equal(v.cfg.postNATSourceIPv4Address))
		}
		if v.cfg.postNAPTSourceTransportPort != 0 {
			gomega.Expect(r["postNAPTSourceTransportPort"]).
				To(gomega.Equal(v.cfg.postNAPTSourceTransportPort))
		}
	}

	v.verifyIPFIXSharedRecords()
}

func (v *ipfixVerifier) verifyIPFIXFlowUsageRecords() {
	uplinkVRFName := "ipv4-VRF:200"
	if v.f.IPMode == framework.UPGIPModeV6 {
		uplinkVRFName = "ipv6-VRF:200"
	}
	if v.cfg.expectedUplinkVRFName != "" {
		uplinkVRFName = v.cfg.expectedUplinkVRFName
	}

	for _, r := range v.recs {
		gomega.Expect(r).To(gomega.HaveKey("interfaceName"))
		gomega.Expect(r).To(gomega.HaveKeyWithValue("observationDomainName", "test-domain"))
		gomega.Expect(r).To(gomega.HaveKeyWithValue("observationPointId", uint64(4242)))

		gomega.Expect(r["VRFname"]).To(gomega.Equal(uplinkVRFName))
		gomega.Expect(r["interfaceName"]).To(gomega.Equal("sgi0"))
	}

	v.verifyIPFIXSharedRecords()
}

func (v *ipfixVerifier) verifyReportingInterval(expectedSeconds int) {
	var times []time.Time
	for _, r := range v.recs {
		times = append(times, r["ts"].(time.Time))
	}
	atLeastMs := uint64(expectedSeconds) * 1000
	verifyIntervals(times, atLeastMs)
}

func verifyIntervals(times []time.Time, atLeastMs uint64) {
	gomega.Expect(len(times)).To(gomega.BeNumerically(">", 3))
	// the last interval may be shorter b/c the session is deleted
	for n := 1; n < len(times)-1; n++ {
		deltaT := times[n].Sub(times[n-1]).Milliseconds()
		gomega.Expect(deltaT).To(gomega.BeNumerically(">=", atLeastMs-500))
	}
}
