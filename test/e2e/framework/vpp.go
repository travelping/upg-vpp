package framework

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/pkg/errors"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/core"
	"git.fd.io/govpp.git/examples/binapi/vpe"
	"golang.org/x/sys/unix"
)

const (
	VPP_BINARY               = "/usr/bin/vpp"
	VPP_MAX_CONNECT_ATTEMPTS = 10
	VPP_RECONNECT_INTERVAL   = time.Second
)

type RouteConfig struct {
	Dst *net.IPNet
	Gw  net.IP
}

type VPPNetworkNamespace struct {
	Name          string
	VPPMac        net.HardwareAddr
	VPPIP         *net.IPNet
	OtherIP       *net.IPNet
	VPPLinkName   string
	OtherLinkName string
	Table         int
	NSRoutes      []RouteConfig
}

type VPPConfig struct {
	Namespaces    []VPPNetworkNamespace
	SetupCommands []string
}

type VPPInstance struct {
	cfg        VPPConfig
	conn       *core.Connection
	apiChannel api.Channel
	cmd        *exec.Cmd
	vppNS      *NetNS
	namespaces map[string]*NetNS
	Context    context.Context
	cancel     context.CancelFunc
}

func NewVppInstance(cfg VPPConfig) *VPPInstance {
	return &VPPInstance{
		cfg:        cfg,
		namespaces: make(map[string]*NetNS),
	}
}

func (vi *VPPInstance) GetNS(name string) *NetNS {
	ns, ok := vi.namespaces[name]
	if !ok {
		log.Panicf("namespace %q not found", name)
	}
	return ns
}

func (vi *VPPInstance) VerifyVPPAlive() error {
	if err := vi.Ctl("show version"); err != nil {
		return errors.Wrap(err, "VPP is not alive: error executing 'show upf version'")
	}

	return nil
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

	// FIXME: use proper temp file!!! or pass cmds to the gdb
	ioutil.WriteFile("/tmp/foo", []byte("r\nbt 10\n"), 0700)

	// TODO: check that the process is running
	vi.cmd = exec.Command(
		"nsenter", "--net="+vi.vppNS.Path(),
		"gdb", "--batch", "-x", "/tmp/foo", "--args",
		VPP_BINARY, "-c", startupFile.Name())
	vi.cmd.Stdout = os.Stdout
	vi.cmd.Stderr = os.Stderr
	sigchldCh := make(chan os.Signal, 1)
	signal.Notify(sigchldCh, unix.SIGCHLD)
	if err := vi.cmd.Start(); err != nil {
		return errors.Wrapf(err, "error starting vpp (%q)", VPP_BINARY)
	}

	conn, conev, err := govpp.AsyncConnect(
		socketclient.DefaultSocketName,
		VPP_MAX_CONNECT_ATTEMPTS,
		VPP_RECONNECT_INTERVAL)

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

	var cancel context.CancelFunc
	vi.Context, cancel = context.WithCancel(context.Background())
	pid := vi.cmd.Process.Pid
	go func() {
		defer signal.Stop(sigchldCh)
		for {
			select {
			case <-vi.Context.Done():
			case <-sigchldCh:
				<-time.After(500 * time.Millisecond)
				var s unix.WaitStatus
				wpid, err := unix.Wait4(pid, &s, unix.WNOHANG, nil)
				if err == nil && wpid == 0 {
					continue
				}
				if err != nil {
					fmt.Printf("* Wait4 error: %s\n", err)
				} else {
					fmt.Printf("* VPP process has exited!\n")
				}
				cancel()
				return
			case e := <-conev:
				if e.State == core.Failed {
					cancel()
					return
				}
			}
		}
	}()

	return nil
}

func (vi *VPPInstance) stopVPP() {
	if vi.cancel != nil {
		vi.cancel()
	}

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
}

func (vi *VPPInstance) closeNamespaces() {
	// FIXME (allow tcpdumps to grab the packets)
	<-time.After(1 * time.Second)
	for _, ns := range vi.namespaces {
		ns.Close()
	}
	if vi.vppNS != nil {
		vi.vppNS.Close()
		vi.vppNS = nil
	}
	vi.namespaces = nil
}

func (vi *VPPInstance) TearDown() {
	vi.stopVPP()
	vi.closeNamespaces()
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

	vi.vppNS, err = NewNS("vpp")
	if err != nil {
		vi.closeNamespaces()
		return errors.Wrap(err, "VppNS")
	}
	fmt.Printf("VPP ns: %s\n", vi.vppNS.Path())

	for _, nsCfg := range vi.cfg.Namespaces {
		ns, err := NewNS(nsCfg.Name)
		if err != nil {
			return errors.Wrapf(err, "NewNS: %s", nsCfg.Name)
		}

		if err := vi.vppNS.SetupVethPair(nsCfg.VPPLinkName, nil, ns, nsCfg.OtherLinkName, nsCfg.OtherIP); err != nil {
			return errors.Wrap(err, "SetupVethPair (client)")
		}

		if _, found := vi.namespaces[nsCfg.Name]; found {
			panic("duplicate namespace name")
		}

		for _, rcfg := range nsCfg.NSRoutes {
			if err := ns.AddRoute(rcfg.Dst, rcfg.Gw); err != nil {
				return errors.Wrapf(err, "route for ns %s", nsCfg.Name)
			}
		}

		vi.namespaces[nsCfg.Name] = ns
		fmt.Printf("%s ns: %s; (vpp) %s <--> (other) %s\n", nsCfg.Name, ns.Path(), *nsCfg.VPPIP, *nsCfg.OtherIP)
		c := NewCapture(CaptureConfig{
			Iface: nsCfg.VPPLinkName,
			// FIXME: store pcaps to the specified location not /tmp
			PCAPPath: fmt.Sprintf("/tmp/%s.pcap", nsCfg.OtherLinkName),
			Snaplen:  0,
			TargetNS: vi.vppNS,
		})
		if err := c.Start(); err != nil {
			return errors.Wrapf(err, "capture for %s", nsCfg.Name)
		}
	}

	return nil
}

func (vi *VPPInstance) runCmds(cmds ...string) error {
	for _, cmd := range cmds {
		if err := vi.Ctl("%s", cmd); err != nil {
			return errors.Wrapf(err, "vpp command %q", cmd)
		}
	}

	return nil
}

func (vi *VPPInstance) interfaceCmds(nsCfg VPPNetworkNamespace) []string {
	var cmds []string
	ipCmd := "ip"
	if nsCfg.VPPIP.IP.To4() == nil {
		ipCmd = "ip6"
	}
	if nsCfg.Table != 0 {
		cmds = append(cmds,
			fmt.Sprintf("%s table add %d", ipCmd, nsCfg.Table))
	}
	return append(cmds,
		fmt.Sprintf("create host-interface name %s", nsCfg.VPPLinkName),
		fmt.Sprintf("set interface mac address host-%s %s", nsCfg.VPPLinkName, nsCfg.VPPMac),
		fmt.Sprintf("set interface %s table host-%s %d", ipCmd, nsCfg.VPPLinkName, nsCfg.Table),
		fmt.Sprintf("set interface ip address host-%s %s", nsCfg.VPPLinkName, nsCfg.VPPIP),
		fmt.Sprintf("set interface state host-%s up", nsCfg.VPPLinkName),
	)
}

func (vi *VPPInstance) Configure() error {
	var allCmds []string
	for _, nsCfg := range vi.cfg.Namespaces {
		allCmds = append(allCmds, vi.interfaceCmds(nsCfg)...)
	}
	allCmds = append(allCmds, vi.cfg.SetupCommands...)
	return vi.runCmds(allCmds...)
}

// TODO: !!! separate log and socket paths for VPPs !!!
