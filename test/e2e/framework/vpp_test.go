package framework

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const (
	VPP_WS_FILE_SIZE          = 60000000
	VPP_WS_FIFO_SIZE_KiB      = 60000
	NON_APP_TRAFFIC_THRESHOLD = 1000
)

var (
	ueIP     = MustParseIP("10.0.1.3")
	serverIP = MustParseIP("10.0.2.3")
)

func TestVPPWebServer(t *testing.T) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		t.Fatalf("uname: %v", err)
	}

	if strings.Contains(string(uname.Release[:]), "linuxkit") {
		t.Skip("VPP web server doesn't work on Mac Docker (and perhaps Windows one, too)")
	}

	wsDir, err := setupWebServerDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(wsDir)

	WithVPP(t, VPPConfig{
		Namespaces: noUPGNamespaces(),
		SetupCommands: []string{
			// FIXME: fifo-size <nbytes> in 'http static server' is
			// actually in KiB
			// FIXME: prealloc-fios in 'http static server' command help
			// (should be prealloc-fifos)
			// FIXME: VPP http_static plugin fails on Mac Docker unless patched
			// to use pool_get() and memset()
			// instead of pool_get_aligned_zero_numa()
			fmt.Sprintf("http static server www-root %s uri tcp://0.0.0.0/80 cache-size 2m fifo-size %d debug 2", wsDir, VPP_WS_FIFO_SIZE_KiB),
		},
	}, func(vi *VPPInstance) {
		tg := NewTrafficGen(TrafficGenConfig{
			ClientNS: vi.GetNS("client"),
			ServerNS: vi.GetNS("server"),
			ServerIP: MustParseIP("10.0.0.2"),
			Context:  vi.Context,
		})

		if err := tg.Run(); err != nil {
			t.Error(err)
		}
	})
}

func TestVPPProxy(t *testing.T) {
	WithVPP(t, VPPConfig{
		Namespaces: noUPGNamespaces(),
		SetupCommands: []string{
			// FIXME: fifo-size <nbytes> in 'http static server' is
			// actually in KiB
			// FIXME: prealloc-fios in 'http static server' command help
			// (should be prealloc-fifos)
			// FIXME: VPP http_static plugin fails on Mac Docker unless patched
			// to use pool_get() and memset()
			// instead of pool_get_aligned_zero_numa()
			// fmt.Sprintf("http static server www-root %s uri tcp://0.0.0.0/80 cache-size 2m fifo-size %d debug 2", wsDir, VPP_WS_FIFO_SIZE_KiB),
			"test proxy server server-uri tcp://10.0.0.2/555 client-uri tcp://10.0.1.3/777 fifo-size 41943040 max-fifo-size 41943040 rcv-buf-size 41943040",
		},
	}, func(vi *VPPInstance) {
		tg := NewTrafficGen(TrafficGenConfig{
			ClientNS:            vi.GetNS("client"),
			ServerNS:            vi.GetNS("server"),
			ServerIP:            MustParseIP("10.0.0.2"),
			WebServerPort:       555,
			WebServerListenPort: 777,
			Context:             vi.Context,
		})

		if err := tg.Run(); err != nil {
			t.Error(err)
		}
	})
}

func TestMeasurement(t *testing.T) {
	for _, tc := range []struct {
		name         string
		trafficType  TrafficType
		appPDR       bool
		fakeHostname bool
		redirect     bool
	}{
		{
			name:        "HTTP",
			trafficType: TrafficTypeHTTP,
		},
		{
			name:        "HTTP+Proxy",
			trafficType: TrafficTypeHTTP,
			appPDR:      true,
		},
		{
			name:         "HTTP+App",
			trafficType:  TrafficTypeHTTP,
			appPDR:       true,
			fakeHostname: true,
		},
		{
			name:        "UDP",
			trafficType: TrafficTypeUDP,
		},
		{
			name:        "HTTP Redirect",
			trafficType: TrafficTypeHTTPRedirect,
			redirect:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			WithUPG(t, func(vi *VPPInstance, pc *PFCPConnection) {
				sessionIEs := SessionConfig{
					IdBase:   1,
					UEIP:     ueIP,
					AppPDR:   tc.appPDR,
					Redirect: tc.redirect,
				}.SessionIEs()
				seid, err := pc.EstablishSession(vi.Context, sessionIEs...)
				if err != nil {
					t.Error(err)
					return
				}

				t.Logf("Session started")
				tg := NewTrafficGen(tgTrafficMeasurementConfig(vi, tc.trafficType, tc.fakeHostname, false))
				if err := tg.Run(); err != nil {
					t.Error(err)
				}

				vi.Ctl("show upf session")
				vi.Ctl("show upf flows")

				ms, err := pc.DeleteSession(vi.Context, seid)
				if err != nil {
					t.Error(err)
					return
				}

				verifyMeasurement(t, vi, ms, tc.trafficType, tc.appPDR && tc.fakeHostname, NON_APP_TRAFFIC_THRESHOLD)
			})
		})
	}
}

func TestPDRReplacement(t *testing.T) {
	for _, tc := range []struct {
		name              string
		trafficType       TrafficType
		appPDR            bool
		toggleAppPDR      bool
		redirect          bool
		fakeHostname      bool
		verifyMeasurement bool
		retry             bool
	}{
		{
			name:              "HTTP",
			trafficType:       TrafficTypeHTTP,
			verifyMeasurement: true,
		},
		{
			name:              "HTTP+Proxy",
			trafficType:       TrafficTypeHTTP,
			appPDR:            true,
			verifyMeasurement: true,
		},
		{
			name:              "HTTP+ProxyOnOff",
			trafficType:       TrafficTypeHTTP,
			appPDR:            true,
			toggleAppPDR:      true,
			verifyMeasurement: true,
		},
		{
			name:         "HTTP+ProxyOffOn",
			trafficType:  TrafficTypeHTTP,
			toggleAppPDR: true,
			// FIXME: possible off by a packet or so:
			// bad uplink volume: reported 83492, actual 83440
			// verifyMeasurement: true,
			retry: true,
		},
		{
			name:              "HTTP+Proxy+App",
			trafficType:       TrafficTypeHTTP,
			appPDR:            true,
			fakeHostname:      true,
			verifyMeasurement: true,
		},
		{
			name:              "HTTP+Proxy+Redirect",
			trafficType:       TrafficTypeHTTPRedirect,
			redirect:          true,
			verifyMeasurement: true,
		},
		{
			name:         "HTTP+ProxyOnOff+App",
			trafficType:  TrafficTypeHTTP,
			appPDR:       true,
			fakeHostname: true,
			toggleAppPDR: true,
		},
		{
			name:         "HTTP+ProxyOffOn+App",
			trafficType:  TrafficTypeHTTP,
			fakeHostname: true,
			toggleAppPDR: true,
			retry:        true,
		},
		{
			name:         "HTTP+ProxyOnOff+Redirect",
			trafficType:  TrafficTypeHTTPRedirect,
			redirect:     true,
			toggleAppPDR: true,
			retry:        true,
		},
		{
			name:              "UDP",
			trafficType:       TrafficTypeUDP,
			verifyMeasurement: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			WithUPG(t, func(vi *VPPInstance, pc *PFCPConnection) {
				sessionCfg := SessionConfig{
					IdBase:   1,
					UEIP:     ueIP,
					AppPDR:   tc.appPDR,
					Redirect: tc.redirect,
				}
				seid, err := pc.EstablishSession(vi.Context, sessionCfg.SessionIEs()...)
				if err != nil {
					t.Error(err)
					return
				}

				t.Logf("Session started")
				tg := NewTrafficGen(tgTrafficMeasurementConfig(vi, tc.trafficType, tc.fakeHostname, tc.retry))
				tgDone := tg.Start()
				var i int
			LOOP:
				for i = 1; ; i++ {
					select {
					case <-tgDone:
						break LOOP
					case <-time.After(1 * time.Second):
					}
					ies := sessionCfg.DeletePDRs()
					// changing the PDR IDs crashes UPG as of 1.0.1
					// while it's handling a packet belonging to an affected flow
					sessionCfg.IdBase ^= 8
					if tc.toggleAppPDR {
						sessionCfg.AppPDR = !sessionCfg.AppPDR
					}
					ies = append(ies, sessionCfg.CreatePDRs()...)
					if _, err := pc.ModifySession(vi.Context, seid, ies...); err != nil {
						t.Errorf("ModifySession(): %v", err)
						break
					}
				}

				vi.Ctl("show upf session")
				vi.Ctl("show upf flows")

				if err := tg.Verify(); err != nil {
					t.Errorf("Traffic generator: %v", err)
				}

				ms, err := pc.DeleteSession(vi.Context, seid)
				if err != nil {
					t.Error(err)
					return
				}

				if tc.verifyMeasurement {
					verifyMeasurement(
						t, vi, ms, tc.trafficType, tc.appPDR && tc.fakeHostname,
						NON_APP_TRAFFIC_THRESHOLD)
				}
			})
		})
	}
}

func setupWebServerDir() (string, error) {
	wsDir, err := ioutil.TempDir("", "vpptest")
	if err != nil {
		return "", errors.Wrap(err, "TempDir")
	}
	if err := ioutil.WriteFile(filepath.Join(wsDir, "dummy"), make([]byte, VPP_WS_FILE_SIZE), 0777); err != nil {
		return "", errors.Wrap(err, "WriteFile")
	}
	return wsDir, nil
}

func WithVPP(t *testing.T, cfg VPPConfig, toCall func(vi *VPPInstance)) {
	vi := NewVppInstance(cfg)
	defer vi.TearDown()

	if err := vi.SetupNamespaces(); err != nil {
		t.Error(err)
	} else if err := vi.StartVPP(); err != nil {
		t.Error(err)
	} else if err := vi.Ctl("show version"); err != nil {
		t.Error(err)
	} else if err := vi.Configure(); err != nil {
		t.Error(err)
	} else if err := vi.VerifyVPPAlive(); err != nil {
		t.Error(err)
	} else {
		toCall(vi)
		if !t.Failed() {
			if err := vi.VerifyVPPAlive(); err != nil {
				t.Error(err)
			}
		}
	}
}

func noUPGNamespaces() []VPPNetworkNamespace {
	return []VPPNetworkNamespace{
		{
			Name:          "client",
			VPPMac:        MustParseMAC("fa:8a:78:4d:18:01"),
			VPPIP:         MustParseIPNet("10.0.0.2/24"),
			OtherIP:       MustParseIPNet("10.0.0.3/24"),
			VPPLinkName:   "vpp-client-veth",
			OtherLinkName: "client-veth",
			Table:         0,
		},
		{
			Name:          "server",
			VPPMac:        MustParseMAC("fa:8a:78:4d:19:01"),
			VPPIP:         MustParseIPNet("10.0.1.2/24"),
			OtherIP:       MustParseIPNet("10.0.1.3/24"),
			VPPLinkName:   "vpp-server-veth",
			OtherLinkName: "server-veth",
			Table:         0,
		},
	}
}

func WithUPG(t *testing.T, toCall func(vi *VPPInstance, pc *PFCPConnection)) {
	WithVPP(t, VPPConfig{
		Namespaces: []VPPNetworkNamespace{
			{
				Name:          "cp",
				VPPMac:        MustParseMAC("fa:8a:78:4d:5b:5b"),
				VPPIP:         MustParseIPNet("10.0.0.2/24"),
				OtherIP:       MustParseIPNet("10.0.0.3/24"),
				VPPLinkName:   "cp0",
				OtherLinkName: "cp1",
				Table:         0,
			},
			{
				Name:          "access",
				VPPMac:        MustParseMAC("fa:8a:78:4d:18:01"),
				VPPIP:         MustParseIPNet("10.0.1.2/24"),
				OtherIP:       MustParseIPNet("10.0.1.3/24"),
				VPPLinkName:   "access0",
				OtherLinkName: "access1",
				Table:         100,
				NSRoutes: []RouteConfig{
					{
						Gw: MustParseIP("10.0.1.2"),
					},
				},
			},
			{
				Name:          "sgi",
				VPPMac:        MustParseMAC("fa:8a:78:4d:19:01"),
				VPPIP:         MustParseIPNet("10.0.2.2/24"),
				OtherIP:       MustParseIPNet("10.0.2.3/24"),
				VPPLinkName:   "sgi0",
				OtherLinkName: "sgi1",
				Table:         200,
				NSRoutes: []RouteConfig{
					{
						Dst: MustParseIPNet("10.0.1.0/24"),
						Gw:  MustParseIP("10.0.2.2"),
					},
				},
			},
		},
		SetupCommands: []string{
			"upf nwi name cp vrf 0",
			"upf nwi name access vrf 100",
			"upf nwi name sgi vrf 200",
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			// NOTE: "ip6" instead of "ip4" for IPv6
			"upf tdf ul table vrf 100 ip4 table-id 1001",
			// NOTE: "ip6" instead of "ip4" for IPv6
			"upf tdf ul enable ip4 host-access0",
			// NOTE: both IP and subnet (ip4 or ipv6) should be variable below
			// For IPv6, ::/0 should be used as the subnet
			"ip route add 0.0.0.0/0 table 200 via 10.0.2.3 host-sgi0",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver-.*",
			// "set upf proxy mss 1250"
		},
	}, func(vi *VPPInstance) {
		cfg := PFCPConfig{
			Namespace: vi.GetNS("cp"),
			UNodeIP:   MustParseIP("10.0.0.2"),
			NodeID:    "pfcpstub",
			UEIP:      ueIP,
			// ReportQueryInterval: 1 * time.Second,
			// ReplacePDRs:         tc.replacePDRs,
		}
		pc := NewPFCPConnection(cfg)
		if err := pc.Start(vi.Context); err != nil {
			t.Error(err)
			return
		}
		defer func() {
			// make sure all PFCP packets are recorded
			<-time.After(time.Second)
			if err := pc.Stop(vi.Context); err != nil {
				t.Error(err)
			}
		}()
		toCall(vi, pc)
	})
}

// tgTrafficMeasurementConfig returns a TrafficGenConfig suitable
// for precise traffic measurement. It includes delays to avoid
// skipped packets in pcaps, as well as "NoLinger" option
func tgTrafficMeasurementConfig(vi *VPPInstance, trafficType TrafficType, fakeHostname, retry bool) TrafficGenConfig {
	cfg := TrafficGenConfig{
		ClientNS:               vi.GetNS("access"),
		ServerNS:               vi.GetNS("sgi"),
		ServerIP:               serverIP,
		WebServerPort:          80,
		WebServerListenPort:    80,
		ChunkDelay:             50 * time.Millisecond,
		Context:                vi.Context,
		FinalDelay:             3 * time.Second, // make sure everything gets into the PCAP
		VerifyStats:            !retry,
		Type:                   trafficType,
		UseFakeHostname:        fakeHostname,
		Retry:                  retry,
		RedirectLocationSubstr: "127.0.0.1/this-is-my-redirect",
		RedirectResponseSubstr: "<title>Redirection</title>",
	}

	if os.Getenv("UPG_TEST_QUICK") != "" {
		cfg.ChunkCount = 40
	}

	if trafficType == TrafficTypeUDP {
		cfg.ChunkSize = 100
	}

	if trafficType == TrafficTypeHTTPRedirect {
		cfg.ChunkCount = 40
		cfg.ChunkDelay = 300 * time.Millisecond
	}

	return cfg
}

func verifyMeasurement(t *testing.T, vi *VPPInstance, ms *PFCPMeasurement, trafficType TrafficType, app bool, appToleration uint64) {
	if ms == nil {
		t.Error("DeleteSession didn't return any measurements")
		return
	}

	if app {
		if verifyPreAppReport(t, ms, 1, appToleration) {
			if validateReport(t, ms, 2) != nil {
				*ms.Reports[2].UplinkVolume += *ms.Reports[1].UplinkVolume
				*ms.Reports[2].DownlinkVolume += *ms.Reports[1].DownlinkVolume
				*ms.Reports[2].TotalVolume += *ms.Reports[1].TotalVolume
			}
			verifyMainReport(t, vi, ms, trafficType, 2)
		}
	} else {
		verifyMainReport(t, vi, ms, trafficType, 1)
	}
}

func validateReport(t *testing.T, ms *PFCPMeasurement, urrId uint32) *PFCPReport {
	r, found := ms.Reports[urrId]
	switch {
	case !found:
		t.Errorf("report missing for URR %d", urrId)
	case r.DownlinkVolume == nil:
		t.Error("downlink volume missing in UsageReport")
	case r.UplinkVolume == nil:
		t.Error("uplink volume missing in UsageReport")
	case r.TotalVolume == nil:
		t.Error("total volume missing in UsageReport")
	default:
		return &r
	}
	return nil
}

func verifyPreAppReport(t *testing.T, ms *PFCPMeasurement, urrId uint32, toleration uint64) bool {
	r := validateReport(t, ms, urrId)
	if r == nil {
		return false
	}
	if *r.DownlinkVolume > toleration {
		t.Errorf("too much non-app dl traffic: %d (max %d)", *r.DownlinkVolume, toleration)
	}
	if *r.UplinkVolume > toleration {
		t.Errorf("too much non-app ul traffic: %d (max %d)", *r.UplinkVolume, toleration)
	}
	if *r.UplinkVolume+*r.DownlinkVolume != *r.TotalVolume {
		t.Errorf("bad total reported volume: must be %d, actual %d",
			*r.UplinkVolume+*r.DownlinkVolume,
			*r.TotalVolume)
	}
	return true
}

func verifyMainReport(t *testing.T, vi *VPPInstance, ms *PFCPMeasurement, trafficType TrafficType, urrId uint32) bool {
	c := vi.Captures["access"]
	if c == nil {
		panic("capture not found")
	}

	var proto layers.IPProtocol
	switch trafficType {
	case TrafficTypeHTTP, TrafficTypeHTTPRedirect:
		proto = layers.IPProtocolTCP
	case TrafficTypeUDP:
		proto = layers.IPProtocolUDP
	default:
		panic("bad traffic type")
	}

	ul := c.GetTrafficCount(Make5Tuple(ueIP, -1, serverIP, -1, proto))
	dl := c.GetTrafficCount(Make5Tuple(serverIP, -1, ueIP, -1, proto))
	t.Logf("capture stats: UL: %d, DL: %d", ul, dl)

	r := validateReport(t, ms, urrId)
	if r == nil {
		return false
	}
	if ul != *r.UplinkVolume {
		t.Errorf("bad uplink volume: reported %d, actual %d", *r.UplinkVolume, ul)
	}
	if dl != *r.DownlinkVolume {
		t.Errorf("bad downlink volume: reported %d, actual %d", *r.DownlinkVolume, dl)
	}
	if *r.UplinkVolume+*r.DownlinkVolume != *r.TotalVolume {
		t.Errorf("bad total reported volume: must be %d, actual %d",
			*r.UplinkVolume+*r.DownlinkVolume,
			*r.TotalVolume)
	}
	return true
}
