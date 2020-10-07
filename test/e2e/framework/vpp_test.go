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

	"golang.org/x/sys/unix"
)

const (
	VPP_WS_FILE_SIZE     = 60000000
	VPP_WS_FIFO_SIZE_KiB = 60000
)

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
		t.Fatal(err)
	}
	if err := vi.StartVPP(); err != nil {
		t.Fatal(err)
	}
	if err := vi.Ctl("show version"); err != nil {
		t.Fatal(err)
	}
	if err := vi.Configure(); err != nil {
		t.Fatal(err)
	}

	toCall(vi)
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
		})

		if err := tg.SimulateDownload(); err != nil {
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
			ClientNS:         vi.GetNS("client"),
			ServerNS:         vi.GetNS("server"),
			ServerIP:         MustParseIP("10.0.0.2"),
			ServerPort:       555,
			ServerListenPort: 777,
		})

		if err := tg.StartWebserver(); err != nil {
			t.Error(err)
			return
		}

		if err := tg.SimulateDownload(); err != nil {
			t.Error(err)
		}
	})
}

func TestUPG(t *testing.T) {
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
			// "create upf application proxy name TST",
			// "upf application TST rule 3000 add l7 regex ^https?://theserver/",
			// "set upf proxy mss 1250"
		},
	}, func(vi *VPPInstance) {
		pc := NewPFCPConnection(PFCPConfig{
			Namespace:           vi.GetNS("cp"),
			UNodeIP:             MustParseIP("10.0.0.2"),
			NodeID:              "pfcpstub",
			UEIP:                MustParseIP("10.0.1.3"),
			ReportQueryInterval: 1 * time.Second,
		})
		sessionStartCh, errCh := pc.Start()
		select {
		case <-time.After(30 * time.Second):
			t.Errorf("timed out")
			pc.Stop()
		case err := <-errCh:
			if err != nil {
				t.Error(err)
			} else {
				t.Error("PFCPConnection stopped prematurely (?)")
			}
			return
		case <-sessionStartCh:
			t.Logf("Session started")
			tg := NewTrafficGen(TrafficGenConfig{
				ClientNS:         vi.GetNS("access"),
				ServerNS:         vi.GetNS("sgi"),
				ServerIP:         MustParseIP("10.0.2.3"),
				ServerPort:       80,
				ServerListenPort: 80,
				// FIXME
				ChunkDelay: 50 * time.Millisecond,
			})
			if err := tg.StartWebserver(); err != nil {
				t.Error(err)
				return
			}

			if err := tg.SimulateDownload(); err != nil {
				t.Error(err)
			}
		}

		pc.Stop()

		select {
		case <-time.After(30 * time.Second):
			t.Errorf("timed out")
		case err := <-errCh:
			if err != nil {
				t.Error(err)
			} else {
				t.Logf("Success")
			}
		}
	})
}
