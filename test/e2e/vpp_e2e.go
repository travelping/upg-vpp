package exttest

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/onsi/ginkgo"

	"github.com/travelping/upg-vpp/test/e2e/framework"
	"github.com/travelping/upg-vpp/test/e2e/traffic"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

const (
	VPP_WS_FILE_SIZE     = 60000000
	VPP_WS_FIFO_SIZE_KiB = 60000
)

var _ = ginkgo.Describe("VPP", func() {
	f := framework.NewFramework(framework.UPGModeNone, framework.UPGIPModeNone, &vpp.VPPConfig{
		Namespaces: []vpp.VPPNetworkNamespace{
			{
				Name:          "client",
				VPPMac:        framework.MustParseMAC("fa:8a:78:4d:18:01"),
				VPPIP:         framework.MustParseIPNet("10.0.0.2/24"),
				OtherIP:       framework.MustParseIPNet("10.0.0.3/24"),
				VPPLinkName:   "vpp-client-veth",
				OtherLinkName: "client-veth",
				Table:         0,
			},
			{
				Name:          "server",
				VPPMac:        framework.MustParseMAC("fa:8a:78:4d:19:01"),
				VPPIP:         framework.MustParseIPNet("10.0.1.2/24"),
				OtherIP:       framework.MustParseIPNet("10.0.1.3/24"),
				VPPLinkName:   "vpp-server-veth",
				OtherLinkName: "server-veth",
				Table:         0,
			},
		},
	}, nil)

	ginkgo.It("should be able to run built-in webserver", func() {
		// FIXME: VPP http_static plugin fails on Mac Docker unless patched
		// to use pool_get() and memset()
		// instead of pool_get_aligned_zero_numa()
		if framework.RunningInLinuxkit() {
			ginkgo.Skip("mac docker not supported")
		}
		wsDir, err := setupWebServerDir()
		framework.ExpectNoError(err)
		defer os.RemoveAll(wsDir)
		// FIXME: fifo-size <nbytes> in 'http static server' is
		// actually in KiB
		// FIXME: prealloc-fios in 'http static server' command help
		// (should be prealloc-fifos)
		f.VPP.Ctl("http static server www-root %s uri tcp://0.0.0.0/80 cache-size 2m fifo-size %d debug 2",
			wsDir, VPP_WS_FIFO_SIZE_KiB)
		tg := traffic.NewTrafficGen(&traffic.HTTPConfig{
			ServerIPs: []net.IP{
				framework.MustParseIP("10.0.0.2"),
			},
		}, &traffic.SimpleTrafficRec{})
		clientNS := f.VPP.GetNS("client")
		serverNS := f.VPP.GetNS("server")
		framework.ExpectNoError(tg.Run(f.Context, clientNS, serverNS))
	})

	ginkgo.It("should be able to proxy TCP with its proxy plugin", func() {
		f.VPP.Ctl("test proxy server server-uri tcp://10.0.0.2/555 client-uri tcp://10.0.1.3/777 fifo-size 41943040 max-fifo-size 41943040 rcv-buf-size 41943040")
		tg := traffic.NewTrafficGen(&traffic.HTTPConfig{
			ServerIPs: []net.IP{
				framework.MustParseIP("10.0.0.2"),
			},
			ClientPort: 555,
			ServerPort: 777,
		}, &traffic.PreciseTrafficRec{})
		clientNS := f.VPP.GetNS("client")
		serverNS := f.VPP.GetNS("server")
		framework.ExpectNoError(tg.Run(f.Context, clientNS, serverNS))
	})
})

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
