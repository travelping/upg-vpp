package framework

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/core"
	"git.fd.io/govpp.git/examples/binapi/vpe"
	iptools "github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
)

const (
	MTU           = 9000
	VPP_BINARY    = "/usr/bin/vpp"
	VPP_IP        = "10.0.0.2"
	VPP_IP_NET    = VPP_IP + "/24"
	CLIENT_IP_NET = "10.0.0.3/24"
	FILE_SIZE     = 60000000
	FIFO_SIZE_KiB = 60000
)

// exec /etc/vpp/init.conf

// TODO: proper CPU pinning
// TODO: offload off
// TODO: pcaps

var vppStartup = `
unix {
  nodaemon
  log /tmp/vpp.log
  coredump-size unlimited
  full-coredump
  gid vpp
  interactive
  cli-listen /run/vpp/cli.sock
}

socksvr {
  default
}

api-trace {
  on
}

api-segment {
  gid vpp
}

cpu {
  workers 0
}

statseg {
  size 512M
}

plugins {
  path /usr/lib/x86_64-linux-gnu/vpp_plugins/
  plugin dpdk_plugin.so { disable }
}

`

// vlib {
// 	elog-events 10000000
// 	elog-post-mortem-dump
// }

func mustParseAddr(addr string) *netlink.Addr {
	r, err := netlink.ParseAddr(addr)
	if err != nil {
		log.Panicf("failed to parse address %q: %v", addr, err)
	}
	return r
}

type VPPInstance struct {
	conn                                    *core.Connection
	apiChannel                              api.Channel
	cmd                                     *exec.Cmd
	clientNS, vppNS                         ns.NetNS
	vppSideClientLink, clientSideClientLink net.Interface
	webServerDir                            string
}

func (vi *VPPInstance) StartVPP() error {
	startupFile, err := ioutil.TempFile("", "startup-*.conf")
	if err != nil {
		return errors.Wrap(err, "error creating the startup conf file")
	}
	defer os.Remove(startupFile.Name())

	if _, err := startupFile.Write([]byte(vppStartup)); err != nil {
		return errors.Wrap(err, "error writing the startup conf file")
	}

	// // FIXME: use proper temp file!!! or pass cmds to the gdb
	// ioutil.WriteFile("/tmp/foo", []byte("r\nbt\n"), 0700)

	// TODO: check that the process is running
	vi.cmd = exec.Command(
		"nsenter", "--net="+vi.vppNS.Path(),
		// "gdb", "--batch", "-x", "/tmp/foo", "--args",
		VPP_BINARY, "-c", startupFile.Name())
	vi.cmd.Stdout = os.Stdout
	vi.cmd.Stderr = os.Stderr
	if err := vi.cmd.Start(); err != nil {
		return errors.Wrapf(err, "error starting vpp (%q)", VPP_BINARY)
	}

	time.Sleep(time.Second)

	conn, conev, err := govpp.AsyncConnect(
		socketclient.DefaultSocketName,
		core.DefaultMaxReconnectAttempts,
		core.DefaultReconnectInterval)

	if err != nil {
		return errors.Wrapf(err, "error connecting to vpp socket at %q", socketclient.DefaultSocketName)
	}

	// wait for Connected event
	select {
	case e := <-conev:
		switch e.State {
		case core.Connected:
			break
		case core.Disconnected:
			return errors.New("socket disconnected")
		case core.Failed:
			return errors.Wrap(e.Error, "error connecting to VPP")
		}
	}

	vi.conn = conn

	vi.apiChannel, err = conn.NewAPIChannel()
	if err != nil {
		return errors.Wrap(err, "NewAPIChannel")
	}

	return nil
}

func (vi *VPPInstance) setupWebServerDir() error {
	var err error
	vi.webServerDir, err = ioutil.TempDir("", "vpptest")
	if err != nil {
		return errors.Wrap(err, "TempDir")
	}
	if err := ioutil.WriteFile(filepath.Join(vi.webServerDir, "dummy"), make([]byte, FILE_SIZE), 0777); err != nil {
		return errors.Wrap(err, "WriteFile")
	}
	return nil
}

func (vi *VPPInstance) stopVPP() {
	if vi.apiChannel != nil {
		vi.apiChannel.Close()
		vi.apiChannel = nil
	}

	if vi.conn != nil {
		vi.conn.Disconnect()
		vi.conn = nil
	}

	if vi.cmd == nil {
		return
	}
	vi.cmd.Process.Kill()
	vi.cmd.Wait()
	vi.cmd = nil
}

func (vi *VPPInstance) closeNamespaces() {
	for _, netns := range []ns.NetNS{vi.clientNS, vi.vppNS} {
		if netns != nil {
			netns.Close()
			testutils.UnmountNS(netns)
		}
	}
}

func (vi *VPPInstance) TearDown() {
	vi.stopVPP()
	vi.closeNamespaces()
	if vi.webServerDir != "" {
		os.RemoveAll(vi.webServerDir)
	}
}

func (vi *VPPInstance) Ctl(format string, args ...interface{}) error {
	command := fmt.Sprintf(format, args...)
	fmt.Printf(">>> %s\n", command)
	req := &vpe.CliInband{Cmd: command}
	reply := new(vpe.CliInbandReply)
	if err := vi.apiChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return errors.Wrap(err, "binapi request failed:")
	}
	if reply.Reply != "" {
		fmt.Println(reply.Reply)
	}
	return nil
}

func (vi *VPPInstance) SetupNamespaces() error {
	var err error

	vi.clientNS, err = testutils.NewNS()
	if err != nil {
		return errors.Wrap(err, "NewNS")
	}

	vi.vppNS, err = testutils.NewNS()
	if err != nil {
		vi.closeNamespaces()
		return errors.Wrap(err, "vppNS")
	}

	if err := vi.vppNS.Do(func(_ ns.NetNS) error {
		// VPP netns is the "container namespace" here
		// Client netns is the "host namespace" here
		vi.clientSideClientLink, vi.vppSideClientLink, err = iptools.SetupVethWithName("vpp-eth", "client-veth", MTU, vi.clientNS)
		if err != nil {
			return errors.Wrap(err, "creating veth pair")
		}

		return nil
	}); err != nil {
		return err
	}

	if err := vi.clientNS.Do(func(_ ns.NetNS) error {
		veth, err := netlink.LinkByName(vi.clientSideClientLink.Name)
		if err != nil {
			return errors.Wrap(err, "locating client link in the client netns")
		}

		if err := netlink.AddrAdd(veth, mustParseAddr(CLIENT_IP_NET)); err != nil {
			return errors.Errorf("failed to set address for the bridge: %v", err)
		}

		return nil
	}); err != nil {
		return err
	}

	fmt.Printf("VPP ns: %s\n", vi.vppNS.Path())
	fmt.Printf("Client ns: %s\n", vi.clientNS.Path())
	return nil
}

func (vi *VPPInstance) SetupWebserver() error {
	if err := vi.setupWebServerDir(); err != nil {
		return err
	}

	cmds := []string{
		fmt.Sprintf("create host-interface name %s", vi.vppSideClientLink.Name),
		fmt.Sprintf("set interface state host-%s up", vi.vppSideClientLink.Name),
		fmt.Sprintf("set interface ip address host-%s %s", vi.vppSideClientLink.Name, VPP_IP_NET),
		// FIXME: fifo-size <nbytes> in 'http static server' is
		// actually in KiB
		// FIXME: prealloc-fios in 'http static server' command help
		// (should be prealloc-fifos)
		fmt.Sprintf("http static server www-root %s uri tcp://0.0.0.0/80 cache-size 2m fifo-size %d debug 2", vi.webServerDir, FIFO_SIZE_KiB),
	}

	for _, cmd := range cmds {
		if err := vi.Ctl("%s", cmd); err != nil {
			return errors.Wrapf(err, "vpp command %q", cmd)
		}
	}

	return nil
}

func (vi *VPPInstance) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// TODO: Right now, it's important to pass a single IPv4 /
	// IPv6 address here, otherwise DialContext will try multiple
	// connections in parallel, spawning goroutines which can get
	// other network namespace.
	//
	// As it can easily be seen, this approach is rather fragile,
	// and chances are we could improve the situation by using
	// Control hook in the net.Dialer. The Control function could
	// check if the correct network namespace is being used, and
	// if it isn't the case, call runtime.LockOSThread() and
	// switch to the right one.
	var err error
	var conn net.Conn
	fmt.Println("ZZZZZ: dial\n")
	err = vi.clientNS.Do(func(_ ns.NetNS) error {
		var innerErr error
		conn, innerErr = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, address)
		return innerErr
	})
	return conn, err
}

func (vi *VPPInstance) downloadURL() string {
	return fmt.Sprintf("http://%s/dummy", VPP_IP)
}

func (vi *VPPInstance) SimulateDownload() error {
	return vi.clientNS.Do(func(_ ns.NetNS) error {
		ts := time.Now()
		fmt.Printf("*** downloading from %s\n", vi.downloadURL())

		c := http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           vi.dialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		resp, err := c.Get(vi.downloadURL())
		if err != nil {
			return errors.Wrap(err, "HTTP GET")
		}
		defer resp.Body.Close()

		content, err := ioutil.ReadAll(resp.Body)

		if len(content) != FILE_SIZE {
			return errors.Errorf("bad file size. Expected %d, got %d bytes",
				FILE_SIZE, len(content))
		}

		elapsed := time.Since(ts)
		fmt.Printf("*** downloaded %d bytes in %s (~%g Mbps)\n",
			len(content), elapsed,
			float64(len(content))*8.0*float64(time.Second)/(1000000.*float64(elapsed)))

		return nil
	})
}
