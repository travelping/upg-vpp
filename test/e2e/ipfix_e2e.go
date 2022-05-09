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

func describeIPFIX(mode framework.UPGMode, ipMode framework.UPGIPMode) {
	ginkgo.Context("[ipfix]", func() {

		ginkgo.Context("[FAR-based]", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}

			ginkgo.Context("'none' template", func() {
				v.withIPFIXHandler()

				ginkgo.It("doesn't send IPFIX reports", func() {
					v.expectNoTemplates()
					v.verifyIPFIX(ipfixVerifierCfg{
						trafficCfg: &traffic.UDPPingConfig{},
						protocol:   layers.IPProtocolUDP,
					})
					v.verifyNoRecs()
				})
			})

			ginkgo.Context("default template", func() {
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate: "default",
						trafficCfg:  smallVolumeHTTPConfig(nil),
						protocol:    layers.IPProtocolTCP,
						// IPFIX templates are only expected after the session starts as they're
						// specified in NWI
						lateTemplateIDs:     []uint16{256, 257},
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXDefaultRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "default",
						trafficCfg:          &traffic.UDPPingConfig{},
						protocol:            layers.IPProtocolUDP,
						lateTemplateIDs:     []uint16{256, 257},
						expectedTrafficPort: 12345,
					})
					v.verifyIPFIXDefaultRecords()
				})
			})

			ginkgo.Context("dest template", func() {
				v.withIPFIXHandler()

				ginkgo.It("sends IPFIX reports as requested [TCP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate: "dest",
						trafficCfg:  smallVolumeHTTPConfig(nil),
						protocol:    layers.IPProtocolTCP,
						// IPFIX templates are only expected after the session starts as they're
						// specified in NWI
						lateTemplateIDs:     []uint16{256, 257},
						expectedTrafficPort: 80,
					})
					v.verifyIPFIXDestRecords()
				})

				ginkgo.It("sends IPFIX reports as requested [UDP]", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						farTemplate:         "dest",
						trafficCfg:          &traffic.UDPPingConfig{},
						protocol:            layers.IPProtocolUDP,
						lateTemplateIDs:     []uint16{256, 257},
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

			ginkgo.Context("default template", func() {
				f := framework.NewDefaultFramework(mode, ipMode)
				v := &ipfixVerifier{f: f}
				v.withNWIIPFIXPolicy("default")
				// Templates 256 and 257 are expected early because IPFIX policy
				// is specified per NWI
				v.withIPFIXHandler(256, 257)

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
				v.withIPFIXHandler(256, 257)

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
				v.withIPFIXHandler(256, 257)

				ginkgo.BeforeEach(func() {
					setupNAT(f)
				})

				ginkgo.It("includes NAT fields in IPFIX reports", func() {
					v.verifyIPFIX(ipfixVerifierCfg{
						trafficCfg:                  smallVolumeHTTPConfig(nil),
						protocol:                    layers.IPProtocolTCP,
						expectedTrafficPort:         80,
						natPoolName:                 "testing",
						postNATSourceIPv4Address:    framework.MustParseIP("144.0.0.20").To4(),
						postNAPTSourceTransportPort: 10128,
					})
					v.verifyIPFIXDefaultRecords()
				})
			})
		}

		ginkgo.Context("[alt collector]", func() {
			f := framework.NewDefaultFramework(mode, ipMode)
			v := &ipfixVerifier{f: f}
			v.withAltCollector()
			v.withIPFIXHandler(256, 257)

			ginkgo.It("sends IPFIX packets to the specified collector", func() {
				gomega.Expect(v.collectorIP).NotTo(gomega.BeNil())
				v.verifyIPFIX(ipfixVerifierCfg{
					// NOTE: no farTemplate
					trafficCfg:          smallVolumeHTTPConfig(nil),
					protocol:            layers.IPProtocolTCP,
					expectedTrafficPort: 80,
				})
				v.verifyIPFIXDefaultRecords()
			})
		})
	})
}

type ipfixVerifierCfg struct {
	farTemplate                 string
	trafficCfg                  traffic.TrafficConfig
	expectedTrafficPort         uint16
	protocol                    layers.IPProtocol
	lateTemplateIDs             []uint16
	natPoolName                 string
	postNATSourceIPv4Address    net.IP
	postNAPTSourceTransportPort uint16
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
}

func (v *ipfixVerifier) expectTemplates(templateIDs []uint16) {
	ginkgo.By("waiting for the templates...")
	gomega.Eventually(func() bool {
		return v.ipfixHandler.haveTemplateIDs(templateIDs...)
	}, 20*time.Second, 1*time.Second).Should(gomega.BeTrue())
}

func (v *ipfixVerifier) expectNoTemplates() {
	gomega.Consistently(func() bool {
		// 1st template ID is always 256
		return !v.ipfixHandler.haveTemplateIDs(256)
	}, 5*time.Second, 1*time.Second).Should(gomega.BeTrue())
}

func (v *ipfixVerifier) withIPFIXHandler(initialTemplateIDs ...uint16) {
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
		if len(initialTemplateIDs) != 0 {
			v.expectTemplates(initialTemplateIDs)
		}
	})

	ginkgo.AfterEach(func() {
		defer v.ipfixHandler.stop()
		v.collectorIP = nil
	})
}

func (v *ipfixVerifier) withNWIIPFIXPolicy(name string) {
	for n, nwi := range v.f.VPPCfg.NWIs {
		if nwi.Name == "sgi" {
			v.f.VPPCfg.NWIs[n].IPFIXPolicy = name
		}
	}
}

func (v *ipfixVerifier) getCollectorIP() net.IP {
	if v.collectorIP == nil {
		v.collectorIP = v.f.AddCNodeIP()
	}
	return v.collectorIP
}

func (v *ipfixVerifier) withAltCollector() {
	v.f.VPPCfg.IPFIXExporters = append(v.f.VPPCfg.IPFIXExporters,
		vpp.IPFIXExporterConfig{
			GetCollectorIP: v.getCollectorIP,
			GetSrcIP: func() net.IP {
				return v.f.PFCPCfg.UNodeIP
			},
			Port: IPFIX_PORT,
			VRF:  0,
		})

	for n, nwi := range v.f.VPPCfg.NWIs {
		if nwi.Name == "sgi" {
			v.f.VPPCfg.NWIs[n].IPFIXPolicy = "default"
			v.f.VPPCfg.NWIs[n].GetIPFIXCollectorIP = v.getCollectorIP
		}
	}
}

func (v *ipfixVerifier) verifyIPFIX(cfg ipfixVerifierCfg) {
	v.cfg = cfg
	v.seid = startMeasurementSession(v.f, &framework.SessionConfig{
		IMSI:          "313460000000001",
		IPFIXTemplate: cfg.farTemplate,
		NatPoolName:   cfg.natPoolName,
	})
	if len(cfg.lateTemplateIDs) != 0 {
		// for FAR-based IPFIX policies, the templates are added when the session begins
		v.expectTemplates(cfg.lateTemplateIDs)
	}
	sessionStr, err := v.f.VPP.Ctl("show upf session")
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	gomega.Expect(sessionStr).To(gomega.ContainSubstring("313460000000001"))
	runTrafficGen(v.f, cfg.trafficCfg, &traffic.PreciseTrafficRec{})
	ginkgo.By("waiting for the flow to expire")
	gomega.Eventually(func() string {
		flowStr, err := v.f.VPP.Ctl("show upf flows")
		framework.ExpectNoError(err)
		return flowStr
	}, 80*time.Second, 5*time.Second).
		ShouldNot(gomega.ContainSubstring("proto 0x"),
			"the flow should be gone")
	v.ms = deleteSession(v.f, v.seid, true)
	verifyNonAppMeasurement(v.f, v.ms, cfg.protocol, nil)

	v.recs = v.ipfixHandler.getRecords()
}

func (v *ipfixVerifier) verifyNoRecs() {
	gomega.Expect(v.recs).To(gomega.BeEmpty())
}

func (v *ipfixVerifier) verifyIPFIXDefaultRecords() {
	// total counts not used for now, but kept here in case if they're needed later
	// var ulPacketCount, dlPacketCount, ulOctets, dlOctets uint64
	var initiatorPackets, responderPackets uint64
	var initiatorOctets, responderOctets uint64
	var clientPort uint16
	for n, r := range v.recs {
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
		// gomega.Expect(r).To(gomega.HaveKey("flowDirection"))
		gomega.Expect(r).To(gomega.HaveKey("initiatorPackets"))
		gomega.Expect(r).To(gomega.HaveKey("responderPackets"))
		gomega.Expect(r).To(gomega.HaveKey("initiatorOctets"))
		gomega.Expect(r).To(gomega.HaveKey("responderOctets"))
		initiatorPackets += r["initiatorPackets"].(uint64)
		responderPackets += r["responderPackets"].(uint64)
		initiatorOctets += r["initiatorOctets"].(uint64)
		responderOctets += r["responderOctets"].(uint64)
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
			// ulPacketCount = r["packetTotalCount"].(uint64)
			// gomega.Expect(r["octetTotalCount"]).To(gomega.BeNumerically(">=", ulOctets))
			// ulOctets = r["octetTotalCount"].(uint64)
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
			// FIXME: the first record has postNAPTSourceTransportPort of 0
			if n > 0 && v.cfg.postNAPTSourceTransportPort != 0 {
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
			// dlPacketCount = r["packetTotalCount"].(uint64)
			// gomega.Expect(r["octetTotalCount"]).To(gomega.BeNumerically(">=", dlOctets))
			// dlOctets = r["octetTotalCount"].(uint64)
			gomega.Expect(r["sourceTransportPort"]).To(gomega.Equal(v.cfg.expectedTrafficPort))
			if clientPort == 0 {
				clientPort = r["destinationTransportPort"].(uint16)
			} else {
				gomega.Expect(r["destinationTransportPort"]).To(gomega.Equal(clientPort))
			}
			// gomega.Expect(r["flowDirection"]).To(gomega.Equal(uint8(0))) // ingress flow
		}
	}

	// gomega.Expect(ulPacketCount).To(gomega.Equal(*v.ms.Reports[1][0].UplinkPacketCount), "uplink packet count")
	// gomega.Expect(dlPacketCount).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkPacketCount), "downlink packet count")
	gomega.Expect(initiatorPackets).To(gomega.Equal(*v.ms.Reports[1][0].UplinkPacketCount), "initiatorPackets")
	gomega.Expect(responderPackets).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkPacketCount), "responderPackets")
	// gomega.Expect(ulOctets).To(gomega.Equal(*v.ms.Reports[1][0].UplinkVolume), "uplink volume")
	// gomega.Expect(dlOctets).To(gomega.Equal(*v.ms.Reports[1][0].DownlinkVolume), "downlink volume")

	l4UL, l4DL := getL4TrafficCountsFromCapture(v.f, v.cfg.protocol, nil)
	gomega.Expect(initiatorOctets).To(gomega.Equal(l4UL), "initiatorOctets")
	gomega.Expect(responderOctets).To(gomega.Equal(l4DL), "responderOctets")
}

func (v *ipfixVerifier) verifyIPFIXDestRecords() {
	// total counts not used for now, but kept here in case if they're needed later
	// var ulPacketCount, dlPacketCount, ulOctets, dlOctets uint64
	var initiatorOctets, responderOctets uint64
	for _, r := range v.recs {
		gomega.Expect(r).To(gomega.HaveKey("flowEndNanoseconds"))

		dstAddressKey := "destinationIPv4Address"
		if v.f.IPMode == framework.UPGIPModeV6 {
			dstAddressKey = "destinationIPv6Address"
		}
		gomega.Expect(r).To(gomega.HaveKey(dstAddressKey))
		gomega.Expect(r).To(gomega.HaveKey("flowDirection"))
		gomega.Expect(r).To(gomega.HaveKey("initiatorOctets"))
		gomega.Expect(r).To(gomega.HaveKey("responderOctets"))
		initiatorOctets += r["initiatorOctets"].(uint64)
		responderOctets += r["responderOctets"].(uint64)
		if !r[dstAddressKey].(net.IP).Equal(v.f.UEIP()) {
			// upload
			gomega.Expect(r["flowEndNanoseconds"]).To(gomega.BeTemporally(">", v.ulEndTS))
			v.ulEndTS = r["flowEndNanoseconds"].(time.Time)
			gomega.Expect(r[dstAddressKey].(net.IP).Equal(v.f.ServerIP())).To(gomega.BeTrue())
			gomega.Expect(r["flowDirection"]).To(gomega.Equal(uint8(1))) // egress flow
		} else {
			// download
			gomega.Expect(r["flowEndNanoseconds"]).To(gomega.BeTemporally(">=", v.dlEndTS))
			v.dlEndTS = r["flowEndNanoseconds"].(time.Time)
			gomega.Expect(r["flowDirection"]).To(gomega.Equal(uint8(0))) // ingress flow
		}
	}

	l4UL, l4DL := getL4TrafficCountsFromCapture(v.f, v.cfg.protocol, nil)
	gomega.Expect(initiatorOctets).To(gomega.Equal(l4UL), "initiatorOctets")
	gomega.Expect(responderOctets).To(gomega.Equal(l4DL), "responderOctets")
}
