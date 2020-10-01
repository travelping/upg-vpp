package framework

import (
	"fmt"
	"io/ioutil"
	"log"
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
	"github.com/vishvananda/netlink"
)

const (
	VPP_BINARY           = "/usr/bin/vpp"
	VPP_CLIENT_VETH      = "vpp-client-veth"
	VPP_CLIENT_IP        = "10.0.0.2"
	VPP_CLIENT_IP_NET    = VPP_CLIENT_IP + "/24"
	VPP_SERVER_VETH      = "vpp-server-veth"
	VPP_SERVER_IP        = "10.0.1.2"
	VPP_SERVER_IP_NET    = VPP_SERVER_IP + "/24"
	CLIENT_VETH          = "client-veth"
	CLIENT_IP_NET        = "10.0.0.3/24"
	SERVER_VETH          = "server-veth"
	SERVER_IP            = "10.0.1.3"
	SERVER_IP_NET        = SERVER_IP + "/24"
	VPP_WS_FIFO_SIZE_KiB = 60000
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
	conn                      *core.Connection
	apiChannel                api.Channel
	cmd                       *exec.Cmd
	ClientNS, ServerNS, VppNS *NetNS
	webServerDir              string
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
		"nsenter", "--net="+vi.VppNS.Path(),
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
	if err := ioutil.WriteFile(filepath.Join(vi.webServerDir, "dummy"), make([]byte, VPP_WS_FILE_SIZE), 0777); err != nil {
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
	for _, netns := range []*NetNS{vi.ClientNS, vi.VppNS} {
		if netns != nil {
			netns.Close()
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

	vi.ClientNS, err = NewNS()
	if err != nil {
		return errors.Wrap(err, "NewNS")
	}

	vi.ServerNS, err = NewNS()
	if err != nil {
		vi.closeNamespaces()
		return errors.Wrap(err, "NewNS")
	}

	vi.VppNS, err = NewNS()
	if err != nil {
		vi.closeNamespaces()
		return errors.Wrap(err, "VppNS")
	}

	if err := vi.VppNS.SetupVethPair(VPP_CLIENT_VETH, NO_ADDRESS, vi.ClientNS, CLIENT_VETH, CLIENT_IP_NET); err != nil {
		return errors.Wrap(err, "SetupVethPair (client)")
	}

	if err := vi.VppNS.SetupVethPair(VPP_SERVER_VETH, NO_ADDRESS, vi.ServerNS, SERVER_VETH, SERVER_IP_NET); err != nil {
		return errors.Wrap(err, "SetupVethPair (server)")
	}

	fmt.Printf("VPP ns: %s\n", vi.VppNS.Path())
	fmt.Printf("Client ns: %s\n", vi.ClientNS.Path())
	fmt.Printf("Server ns: %s\n", vi.ServerNS.Path())
	return nil
}

func (vi *VPPInstance) ConfigureVPP() error {
	if err := vi.setupWebServerDir(); err != nil {
		return err
	}

	cmds := []string{
		fmt.Sprintf("create host-interface name %s", VPP_CLIENT_VETH),
		fmt.Sprintf("set interface state host-%s up", VPP_CLIENT_VETH),
		fmt.Sprintf("set interface ip address host-%s %s", VPP_CLIENT_VETH, VPP_CLIENT_IP_NET),
		fmt.Sprintf("create host-interface name %s", VPP_SERVER_VETH),
		fmt.Sprintf("set interface state host-%s up", VPP_SERVER_VETH),
		fmt.Sprintf("set interface ip address host-%s %s", VPP_SERVER_VETH, VPP_SERVER_IP_NET),
		// FIXME: fifo-size <nbytes> in 'http static server' is
		// actually in KiB
		// FIXME: prealloc-fios in 'http static server' command help
		// (should be prealloc-fifos)
		fmt.Sprintf("http static server www-root %s uri tcp://0.0.0.0/80 cache-size 2m fifo-size %d debug 2", vi.webServerDir, VPP_WS_FIFO_SIZE_KiB),
		fmt.Sprintf("test proxy server server-uri tcp://%s/555 client-uri tcp://%s/777 fifo-size 41943040 max-fifo-size 41943040 rcv-buf-size 41943040", VPP_CLIENT_IP, SERVER_IP),
	}

	for _, cmd := range cmds {
		if err := vi.Ctl("%s", cmd); err != nil {
			return errors.Wrapf(err, "vpp command %q", cmd)
		}
	}

	return nil
}
