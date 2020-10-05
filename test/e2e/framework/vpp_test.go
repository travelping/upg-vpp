package framework

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
)

const (
	VPP_WS_FIFO_SIZE_KiB = 60000
)

// VPP_CLIENT_VETH      = "vpp-client-veth"
// VPP_CLIENT_IP        = "10.0.0.2"
// VPP_CLIENT_IP_NET    = VPP_CLIENT_IP + "/24"
// VPP_SERVER_VETH      = "vpp-server-veth"
// VPP_SERVER_IP        = "10.0.1.2"
// VPP_SERVER_IP_NET    = VPP_SERVER_IP + "/24"
// CLIENT_VETH          = "client-veth"
// CLIENT_IP_NET        = "10.0.0.3/24"
// SERVER_VETH          = "server-veth"
// SERVER_IP            = "10.0.1.3"
// SERVER_IP_NET        = SERVER_IP + "/24"

// func (vi *VPPInstance) ConfigureProxyAndWebServer() error {
// 	return vi.configureVPP(
// 		fmt.Sprintf("create host-interface name %s", VPP_CLIENT_VETH),
// 		fmt.Sprintf("set interface state host-%s up", VPP_CLIENT_VETH),
// 		fmt.Sprintf("set interface ip address host-%s %s", VPP_CLIENT_VETH, VPP_CLIENT_IP_NET),
// 		fmt.Sprintf("create host-interface name %s", VPP_SERVER_VETH),
// 		fmt.Sprintf("set interface state host-%s up", VPP_SERVER_VETH),
// 		fmt.Sprintf("set interface ip address host-%s %s", VPP_SERVER_VETH, VPP_SERVER_IP_NET),

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

func TestVPP(t *testing.T) {
	wsDir, err := setupWebServerDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(wsDir)

	WithVPP(t, VPPConfig{
		Namespaces: []VPPNetworkNamespace{
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
		},
		SetupCommands: []string{
			// FIXME: fifo-size <nbytes> in 'http static server' is
			// actually in KiB
			// FIXME: prealloc-fios in 'http static server' command help
			// (should be prealloc-fifos)
			fmt.Sprintf("http static server www-root %s uri tcp://0.0.0.0/80 cache-size 2m fifo-size %d debug 2", wsDir, VPP_WS_FIFO_SIZE_KiB),
			"test proxy server server-uri tcp://10.0.0.2/555 client-uri tcp://10.0.1.3/777 fifo-size 41943040 max-fifo-size 41943040 rcv-buf-size 41943040",
		},
	}, func(vi *VPPInstance) {
		tg := NewTrafficGen(vi.GetNS("client"), vi.GetNS("server"), MustParseIP("10.0.0.2"))
		defer tg.TearDown()

		if err := tg.SimulateDownloadFromVPPWebServer(); err != nil {
			t.Fatal(err)
		}

		if err := tg.SimulateDownloadThroughProxy(); err != nil {
			t.Fatal(err)
		}
	})
}
