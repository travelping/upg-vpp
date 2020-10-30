package exttest

import (
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/travelping/upg-vpp/test/e2e/framework"
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
})

func describeMode(title string, mode framework.UPGMode, ipMode framework.UPGIPMode) {
	ginkgo.Context(title, func() {
		f := framework.NewDefaultFramework(mode, ipMode)
		describeMeasurement(f)
		describePDRReplacement(f)
	})
}

func describeMeasurement(f *framework.Framework) {
	ginkgo.Context("session measurement", func() {
		var ms *framework.PFCPMeasurement
		var seid framework.SEID

		sessionContext := func(desc string, cfg framework.SessionConfig, body func()) {
			ginkgo.Context(desc, func() {
				ginkgo.BeforeEach(func() {
					seid = startMeasurementSession(f, &cfg)
				})

				body()
			})
		}

		verifyNonAppTraffic := func(trafficType framework.TrafficType) {
			tg := trafficGen(f, trafficType, framework.TrafficGenConfig{})
			framework.ExpectNoError(tg.Run())
			ms = deleteSession(f, seid)
			verifyNonAppMeasurement(f, ms, trafficType)
		}

		verifyAppTraffic := func(trafficType framework.TrafficType) {
			tg := trafficGen(f, trafficType, framework.TrafficGenConfig{
				// this triggers app detection
				UseFakeHostname: true,
			})
			framework.ExpectNoError(tg.Run())
			ms = deleteSession(f, seid)
			verifyAppMeasurement(f, ms, trafficType)
		}

		sessionContext("[no proxy]", framework.SessionConfig{}, func() {
			ginkgo.It("counts plain HTTP traffic", func() {
				verifyNonAppTraffic(framework.TrafficTypeHTTP)
			})

			ginkgo.It("counts UDP traffic", func() {
				verifyNonAppTraffic(framework.TrafficTypeUDP)
			})
		})

		sessionContext("[proxy]", framework.SessionConfig{AppPDR: true}, func() {
			ginkgo.It("counts plain HTTP traffic (no app hit)", func() {
				verifyNonAppTraffic(framework.TrafficTypeHTTP)
			})

			ginkgo.It("counts traffic for app detection hit on plain HTTP", func() {
				verifyAppTraffic(framework.TrafficTypeHTTP)
			})
		})

		sessionContext("[redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("counts UPG's HTTP redirects", func() {
				verifyNonAppTraffic(framework.TrafficTypeHTTPRedirect)
			})
		})
	})
}

func describePDRReplacement(f *framework.Framework) {
	ginkgo.Context("PDR replacement", func() {
		var ms *framework.PFCPMeasurement
		var seid framework.SEID
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
					sessionCfg.AppPDR = !sessionCfg.AppPDR
				}
				ies = append(ies, sessionCfg.CreatePDRs()...)
				_, err := f.PFCP.ModifySession(f.VPP.Context, seid, ies...)
				framework.ExpectNoError(err)
			}
		}

		verifyNonApp := func(trafficType framework.TrafficType, retry bool) {
			tg := trafficGen(f, trafficType, framework.TrafficGenConfig{
				Retry: retry,
			})
			tgDone := tg.Start()
			pdrReplacementLoop(false, tgDone)
			framework.ExpectNoError(tg.Verify())
			ms = deleteSession(f, seid)
		}

		verifyNonAppTraffic := func(trafficType framework.TrafficType) {
			verifyNonApp(trafficType, false)
			verifyNonAppMeasurement(f, ms, trafficType)
		}

		verifyApp := func(trafficType framework.TrafficType, retry bool) {
			tg := trafficGen(f, trafficType, framework.TrafficGenConfig{
				// this triggers app detection
				UseFakeHostname: true,
				Retry:           retry,
			})
			framework.ExpectNoError(tg.Run())
			ms = deleteSession(f, seid)
		}

		verifyAppTraffic := func(trafficType framework.TrafficType) {
			verifyApp(trafficType, false)
			verifyAppMeasurement(f, ms, trafficType)
		}

		sessionContext("[no proxy]", framework.SessionConfig{}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting", func() {
				verifyNonAppTraffic(framework.TrafficTypeHTTP)
			})

			ginkgo.It("doesn't affect UDP traffic accounting", func() {
				verifyNonAppTraffic(framework.TrafficTypeUDP)
			})
		})

		sessionContext("[proxy]", framework.SessionConfig{AppPDR: true}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting (no app hit)", func() {
				verifyNonAppTraffic(framework.TrafficTypeHTTP)
			})

			ginkgo.It("doesn't affect traffic accounting with app detection hit on plain HTTP", func() {
				verifyAppTraffic(framework.TrafficTypeHTTP)
			})
		})

		sessionContext("[redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("doesn't affect traffic accounting for UPG's HTTP redirects", func() {
				verifyNonAppTraffic(framework.TrafficTypeHTTPRedirect)
			})
		})

		sessionContext("[proxy on-off]", framework.SessionConfig{AppPDR: true}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting (no app hit)", func() {
				verifyNonAppTraffic(framework.TrafficTypeHTTP)
			})

			ginkgo.It("doesn't disrupt traffic with app detection hit on plain HTTP", func() {
				// accounting is obviously disturbed in this case
				// (could be still verified, but harder to do so)
				verifyApp(framework.TrafficTypeHTTP, false)
			})
		})

		sessionContext("[proxy on-off+redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("doesn't disrupt UPG's HTTP redirects", func() {
				verifyNonApp(framework.TrafficTypeHTTPRedirect, false)
			})
		})

		sessionContext("[proxy off-on]", framework.SessionConfig{AppPDR: true}, func() {
			ginkgo.It("doesn't permanently disrupt plain HTTP traffic (no app hit)", func() {
				// FIXME: could also avoid disruptions altogethern
				// and also breaking traffic accounting,
				// but actually it may lose some connections
				// and the accounting may be off by a packet or so, e.g.:
				// bad uplink volume: reported 83492, actual 83440
				verifyNonApp(framework.TrafficTypeHTTP, true)
			})

			ginkgo.It("doesn't permanently disrupt traffic with app detection hit on plain HTTP", func() {
				// accounting is obviously disturbed in this case
				// (could be still verified, but harder to do so)
				verifyApp(framework.TrafficTypeHTTP, true)
			})
		})

		sessionContext("[proxy on-off+redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("doesn't permanently disrupt UPG's HTTP redirects", func() {
				verifyNonApp(framework.TrafficTypeHTTPRedirect, true)
			})
		})
	})
}

type measurementCfg struct {
	trafficType  framework.TrafficType
	appPDR       bool
	fakeHostname bool
	redirect     bool
}

func startMeasurementSession(f *framework.Framework, cfg *framework.SessionConfig) framework.SEID {
	ginkgo.By("starting a PFCP session")
	cfg.IdBase = 1
	cfg.UEIP = f.UEIP()
	cfg.Mode = f.Mode
	if cfg.Mode == framework.UPGModePGW {
		cfg.TEIDPGWs5u = framework.TEIDPGWs5u
		cfg.TEIDSGWs5u = framework.TEIDSGWs5u
		cfg.PGWGRXIP = f.VPPCfg.GetVPPAddress("grx").IP
		cfg.SGWGRXIP = f.VPPCfg.GetNamespaceAddress("grx").IP
	}
	seid, err := f.PFCP.EstablishSession(f.Context, cfg.SessionIEs()...)
	framework.ExpectNoError(err)
	return seid
}

func deleteSession(f *framework.Framework, seid framework.SEID) *framework.PFCPMeasurement {
	f.VPP.Ctl("show upf session")
	f.VPP.Ctl("show upf flows")

	ms, err := f.PFCP.DeleteSession(f.Context, seid)
	framework.ExpectNoError(err)
	return ms
}

func trafficGen(f *framework.Framework, trafficType framework.TrafficType, cfg framework.TrafficGenConfig) *framework.TrafficGen {
	ginkgo.By("starting the traffic generator")

	// this config ensures the possibility of precise measurement
	cfg.ClientNS = f.VPP.GetNS("ue")
	cfg.ServerNS = f.VPP.GetNS("sgi")
	cfg.ServerIP = f.ServerIP()
	cfg.WebServerPort = 80
	cfg.WebServerListenPort = 80
	cfg.ChunkDelay = 50 * time.Millisecond
	cfg.Context = f.Context
	cfg.FinalDelay = 3 * time.Second // make sure everything gets into the PCAP
	cfg.Type = trafficType
	cfg.RedirectLocationSubstr = "127.0.0.1/this-is-my-redirect"
	cfg.RedirectResponseSubstr = "<title>Redirection</title>"
	cfg.VerifyStats = !cfg.Retry

	if os.Getenv("UPG_TEST_QUICK") != "" {
		cfg.ChunkCount = 40
	}

	if trafficType == framework.TrafficTypeUDP {
		cfg.ChunkSize = 100
	}

	if trafficType == framework.TrafficTypeHTTPRedirect {
		cfg.ChunkCount = 40
		cfg.ChunkDelay = 300 * time.Millisecond
	}

	return framework.NewTrafficGen(cfg)
}

func verifyAppMeasurement(f *framework.Framework, ms *framework.PFCPMeasurement, trafficType framework.TrafficType) {
	gomega.Expect(ms).NotTo(gomega.BeNil())

	verifyPreAppReport(ms, 1, NON_APP_TRAFFIC_THRESHOLD)
	validateReport(ms, 2)
	*ms.Reports[2].UplinkVolume += *ms.Reports[1].UplinkVolume
	*ms.Reports[2].DownlinkVolume += *ms.Reports[1].DownlinkVolume
	*ms.Reports[2].TotalVolume += *ms.Reports[1].TotalVolume
	verifyMainReport(f, ms, trafficType, 2)
}

func verifyNonAppMeasurement(f *framework.Framework, ms *framework.PFCPMeasurement, trafficType framework.TrafficType) {
	verifyMainReport(f, ms, trafficType, 1)
}

func validateReport(ms *framework.PFCPMeasurement, urrId uint32) framework.PFCPReport {
	framework.ExpectHaveKey(ms.Reports, urrId, "missing URR id: %d", urrId)
	r := ms.Reports[urrId]
	gomega.Expect(r.DownlinkVolume).ToNot(gomega.BeNil(), "downlink volume missing in the UsageReport")
	gomega.Expect(r.UplinkVolume).ToNot(gomega.BeNil(), "uplink volume missing in the UsageReport")
	gomega.Expect(r.TotalVolume).ToNot(gomega.BeNil(), "total volume missing in the UsageReport")
	framework.ExpectEqual(*r.UplinkVolume+*r.DownlinkVolume, *r.TotalVolume, "bad total volume")
	return r
}

func verifyPreAppReport(ms *framework.PFCPMeasurement, urrId uint32, toleration uint64) {
	r := validateReport(ms, urrId)
	gomega.Expect(*r.DownlinkVolume).To(gomega.BeNumerically("<=", toleration),
		"too much non-app dl traffic: %d (max %d)", *r.DownlinkVolume, toleration)
	gomega.Expect(*r.UplinkVolume).To(gomega.BeNumerically("<=", toleration),
		"too much non-app ul traffic: %d (max %d)", *r.DownlinkVolume, toleration)
}

func verifyMainReport(f *framework.Framework, ms *framework.PFCPMeasurement, trafficType framework.TrafficType, urrId uint32) {
	var c *framework.Capture
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

	var proto layers.IPProtocol
	switch trafficType {
	case framework.TrafficTypeHTTP, framework.TrafficTypeHTTPRedirect:
		proto = layers.IPProtocolTCP
	case framework.TrafficTypeUDP:
		proto = layers.IPProtocolUDP
	default:
		panic("bad traffic type")
	}

	ul := c.GetTrafficCount(framework.Make5Tuple(f.UEIP(), -1, f.ServerIP(), -1, proto))
	dl := c.GetTrafficCount(framework.Make5Tuple(f.ServerIP(), -1, f.UEIP(), -1, proto))
	framework.Logf("capture stats: UL: %d, DL: %d", ul, dl)

	r := validateReport(ms, urrId)
	framework.ExpectEqual(ul, *r.UplinkVolume, "uplink volume for urr %d", urrId)
	framework.ExpectEqual(dl, *r.DownlinkVolume, "downlink volume for urr %d", urrId)
}
