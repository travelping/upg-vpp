package exttest

import (
	"context"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"

	"github.com/travelping/upg-vpp/test/e2e/framework"
	"github.com/travelping/upg-vpp/test/e2e/network"
	"github.com/travelping/upg-vpp/test/e2e/pfcp"
	"github.com/travelping/upg-vpp/test/e2e/traffic"
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
		// TODO: fix these test cases for IPv6
		if ipMode == framework.UPGIPModeV4 {
			describeMTU(mode, ipMode)
		}
	})
}

func describeMeasurement(f *framework.Framework) {
	ginkgo.Context("session measurement", func() {
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
			ms = deleteSession(f, seid)
		}

		sessionContext("[no proxy]", framework.SessionConfig{}, func() {
			ginkgo.It("counts plain HTTP traffic", func() {
				verify(smallVolumeHTTPConfig(nil))
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP)
			})

			ginkgo.It("counts UDP traffic", func() {
				verify(&traffic.UDPPingConfig{})
				verifyNonAppMeasurement(f, ms, layers.IPProtocolUDP)
			})

			ginkgo.It("counts ICMP echo requests and responses", func() {
				verify(&traffic.ICMPPingConfig{})
				proto := layers.IPProtocolICMPv4
				if f.IPMode == framework.UPGIPModeV6 {
					proto = layers.IPProtocolICMPv6
				}
				verifyNonAppMeasurement(f, ms, proto)
			})
		})

		sessionContext("[proxy]", framework.SessionConfig{AppPDR: true}, func() {
			ginkgo.It("counts plain HTTP traffic (no app hit)", func() {
				verify(smallVolumeHTTPConfig(nil))
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP)
			})

			ginkgo.It("counts traffic for app detection hit on plain HTTP", func() {
				verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
					UseFakeHostname: true,
				}))
				verifyAppMeasurement(f, ms, layers.IPProtocolTCP)
			})

			ginkgo.It("can handle a big number of HTTP connections at once", func() {
				verifyConnFlood(f, false)
				deleteSession(f, seid)
			})

			ginkgo.It("can handle a big number of HTTP connections at once [netem]", func() {
				verifyConnFlood(f, true)
				deleteSession(f, seid)
			})

			ginkgo.It("can survive session creation-deletion loop", func() {
				verifySessionDeletionLoop(f, &seid)
			})
		})

		sessionContext("[redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("counts UPG's HTTP redirects", func() {
				verify(&traffic.RedirectConfig{
					RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
					RedirectResponseSubstr: "<title>Redirection</title>",
				})
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP)
			})
		})
	})
}

func describePDRReplacement(f *framework.Framework) {
	ginkgo.Context("PDR replacement", func() {
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
					sessionCfg.AppPDR = !sessionCfg.AppPDR
				}
				ies = append(ies, sessionCfg.CreatePDRs()...)
				_, err := f.PFCP.ModifySession(f.VPP.Context, seid, ies...)
				framework.ExpectNoError(err)
			}
		}

		verify := func(cfg traffic.TrafficConfig, rec traffic.TrafficRec, toggleAppPDR bool) {
			tgDone := startTrafficGen(f, cfg, rec)
			pdrReplacementLoop(toggleAppPDR, tgDone)
			ms = deleteSession(f, seid)
			framework.ExpectNoError(rec.Verify())
		}

		sessionContext("[no proxy]", framework.SessionConfig{}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting", func() {
				verify(smallVolumeHTTPConfig(nil), &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP)
			})

			ginkgo.It("doesn't affect UDP traffic accounting", func() {
				verify(&traffic.UDPPingConfig{}, &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolUDP)
			})
		})

		sessionContext("[proxy]", framework.SessionConfig{AppPDR: true}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting (no app hit)", func() {
				verify(smallVolumeHTTPConfig(nil), &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP)
			})

			ginkgo.It("doesn't affect traffic accounting with app detection hit on plain HTTP", func() {
				verify(smallVolumeHTTPConfig(&traffic.HTTPConfig{
					UseFakeHostname: true,
				}), &traffic.PreciseTrafficRec{}, false)
				verifyAppMeasurement(f, ms, layers.IPProtocolTCP)
			})
		})

		sessionContext("[redirects]", framework.SessionConfig{Redirect: true}, func() {
			ginkgo.It("doesn't affect traffic accounting for UPG's HTTP redirects", func() {
				verify(&traffic.RedirectConfig{
					RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
					RedirectResponseSubstr: "<title>Redirection</title>",
				}, &traffic.PreciseTrafficRec{}, false)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP)
			})
		})

		sessionContext("[proxy on-off]", framework.SessionConfig{AppPDR: true}, func() {
			ginkgo.It("doesn't affect plain HTTP traffic accounting (no app hit)", func() {
				verify(smallVolumeHTTPConfig(nil), &traffic.PreciseTrafficRec{}, true)
				verifyNonAppMeasurement(f, ms, layers.IPProtocolTCP)
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

		sessionContext("[proxy off-on]", framework.SessionConfig{AppPDR: true}, func() {
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

func describeMTU(mode framework.UPGMode, ipMode framework.UPGIPMode) {
	ginkgo.Context("[MTU corner cases]", func() {
		var seid pfcp.SEID

		// TODO: framework should have Clone() method
		// that makes deep copy of the configs (or re-generates them)
		f := framework.NewDefaultFramework(mode, ipMode)
		for i := range f.VPPCfg.Namespaces {
			f.VPPCfg.Namespaces[i].MTU = 1500
		}
		f.GTPUMTU = 9000

		ginkgo.BeforeEach(func() {
			seid = startMeasurementSession(f, &framework.SessionConfig{})
		})

		ginkgo.JustAfterEach(func() {
			deleteSession(f, seid)
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
		cfg.PGWGRXIP = f.VPPCfg.GetVPPAddress("grx").IP
		cfg.SGWGRXIP = f.VPPCfg.GetNamespaceAddress("grx").IP
	}
	seid, err := f.PFCP.EstablishSession(f.Context, cfg.SessionIEs()...)
	framework.ExpectNoError(err)
	return seid
}

func deleteSession(f *framework.Framework, seid pfcp.SEID) *pfcp.PFCPMeasurement {
	f.VPP.Ctl("show upf session")
	f.VPP.Ctl("show upf flows")

	ms, err := f.PFCP.DeleteSession(f.Context, seid)
	framework.ExpectNoError(err)
	return ms
}

func newTrafficGen(f *framework.Framework, cfg traffic.TrafficConfig, rec traffic.TrafficRec) (*traffic.TrafficGen, *network.NetNS, *network.NetNS) {
	ginkgo.By("starting the traffic generator")
	cfg.SetNoLinger(true)
	cfg.SetServerIP(f.ServerIP())
	clientNS := f.VPP.GetNS("ue")
	serverNS := f.VPP.GetNS("sgi")
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
				deleteSession(f, *seid)
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

func verifyAppMeasurement(f *framework.Framework, ms *pfcp.PFCPMeasurement, proto layers.IPProtocol) {
	gomega.Expect(ms).NotTo(gomega.BeNil())

	verifyPreAppReport(ms, 1, NON_APP_TRAFFIC_THRESHOLD)
	validateReport(ms, 2)
	*ms.Reports[2].UplinkVolume += *ms.Reports[1].UplinkVolume
	*ms.Reports[2].DownlinkVolume += *ms.Reports[1].DownlinkVolume
	*ms.Reports[2].TotalVolume += *ms.Reports[1].TotalVolume
	verifyMainReport(f, ms, proto, 2)
}

func verifyNonAppMeasurement(f *framework.Framework, ms *pfcp.PFCPMeasurement, proto layers.IPProtocol) {
	verifyMainReport(f, ms, proto, 1)
}

func validateReport(ms *pfcp.PFCPMeasurement, urrId uint32) pfcp.PFCPReport {
	framework.ExpectHaveKey(ms.Reports, urrId, "missing URR id: %d", urrId)
	r := ms.Reports[urrId]
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

func verifyMainReport(f *framework.Framework, ms *pfcp.PFCPMeasurement, proto layers.IPProtocol, urrId uint32) {
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

	ul := c.GetTrafficCount(network.Make5Tuple(f.UEIP(), -1, f.ServerIP(), -1, proto))
	dl := c.GetTrafficCount(network.Make5Tuple(f.ServerIP(), -1, f.UEIP(), -1, proto))
	framework.Logf("capture stats: UL: %d, DL: %d", ul, dl)

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
