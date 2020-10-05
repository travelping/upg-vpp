package framework

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/core"
	"git.fd.io/govpp.git/examples/binapi/vpe"
)

const (
	VPP_BINARY = "/usr/bin/vpp"
)

type VPPNetworkNamespace struct {
	Name          string
	VPPMac        net.HardwareAddr
	VPPIP         *net.IPNet
	OtherIP       *net.IPNet
	VPPLinkName   string
	OtherLinkName string
	Table         int
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
	if vi.vppNS != nil {
		vi.vppNS.Close()
		vi.vppNS = nil
	}
	for _, ns := range vi.namespaces {
		ns.Close()
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

	vi.vppNS, err = NewNS()
	if err != nil {
		vi.closeNamespaces()
		return errors.Wrap(err, "VppNS")
	}
	fmt.Printf("VPP ns: %s\n", vi.vppNS.Path())

	for _, nsCfg := range vi.cfg.Namespaces {
		ns, err := NewNS()
		if err != nil {
			return errors.Wrapf(err, "NewNS: %s", nsCfg.Name)
		}

		if err := vi.vppNS.SetupVethPair(nsCfg.VPPLinkName, nil, ns, nsCfg.OtherLinkName, nsCfg.OtherIP); err != nil {
			return errors.Wrap(err, "SetupVethPair (client)")
		}

		if _, found := vi.namespaces[nsCfg.Name]; found {
			panic("duplicate namespace name")
		}

		vi.namespaces[nsCfg.Name] = ns
		fmt.Printf("%s ns: %s; (vpp) %s <--> (other) %s\n", nsCfg.Name, ns.Path(), *nsCfg.VPPIP, *nsCfg.OtherIP)
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

// TODO: offload off
// TODO: pcaps
