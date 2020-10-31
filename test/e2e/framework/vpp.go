package framework

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"time"

	"github.com/pkg/errors"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/binapi/vpe"
	"git.fd.io/govpp.git/core"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	VPP_MAX_CONNECT_ATTEMPTS = 10
	VPP_RECONNECT_INTERVAL   = time.Second
	VPP_STARTUP_TIMEOUT      = 5 * time.Second
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
	SkipVPPConfig bool
	L3Capture     bool
}

type VPPConfig struct {
	Namespaces    []VPPNetworkNamespace
	SetupCommands []string
}

func (cfg VPPConfig) GetVPPAddress(namespace string) *net.IPNet {
	for _, ns := range cfg.Namespaces {
		if ns.Name == namespace {
			return ns.VPPIP
		}
	}

	panic("No network namespace: " + namespace)
}

func (cfg VPPConfig) GetNamespaceAddress(namespace string) *net.IPNet {
	for _, ns := range cfg.Namespaces {
		if ns.Name == namespace {
			return ns.OtherIP
		}
	}

	panic("No network namespace: " + namespace)
}

func (cfg VPPConfig) GetNamespaceLinkName(namespace string) string {
	for _, ns := range cfg.Namespaces {
		if ns.Name == namespace {
			return ns.OtherLinkName
		}
	}

	panic("No network namespace: " + namespace)
}

type VPPInstance struct {
	cfg        VPPConfig
	startupCfg VPPStartupConfig
	conn       *core.Connection
	apiChannel api.Channel
	cmd        *exec.Cmd
	vppNS      *NetNS
	namespaces map[string]*NetNS
	Context    context.Context
	cancel     context.CancelFunc
	Captures   map[string]*Capture
	log        *logrus.Entry
	pipeCopyWG sync.WaitGroup
}

func NewVPPInstance(cfg VPPConfig) *VPPInstance {
	var startupCfg VPPStartupConfig
	startupCfg.SetFromEnv()
	context, cancel := context.WithCancel(context.Background())
	return &VPPInstance{
		cfg:        cfg,
		startupCfg: startupCfg,
		namespaces: make(map[string]*NetNS),
		Captures:   make(map[string]*Capture),
		Context:    context,
		cancel:     cancel,
		log:        logrus.NewEntry(logrus.StandardLogger()),
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

	if _, err := startupFile.Write([]byte(vi.startupCfg.Get())); err != nil {
		return errors.Wrap(err, "error writing the startup conf file")
	}

	// FIXME: use proper temp file!!! or pass cmds to the gdb
	ioutil.WriteFile("/tmp/foo", []byte("r\nbt 10\n"), 0700)

	// TODO: check that the process is running
	vi.cmd = exec.Command(
		"nsenter", "--net="+vi.vppNS.Path(),
		"gdb", "--batch", "-x", "/tmp/foo", "--args",
		vi.startupCfg.BinaryPath, "-c", startupFile.Name())

	stdout, err := vi.cmd.StdoutPipe()
	if err != nil {
		return errors.Wrap(err, "StdoutPipe")
	}
	stderr, err := vi.cmd.StderrPipe()
	if err != nil {
		return errors.Wrap(err, "StderrPipe")
	}
	sigchldCh := make(chan os.Signal, 1)
	signal.Notify(sigchldCh, unix.SIGCHLD)
	if err := vi.cmd.Start(); err != nil {
		return errors.Wrapf(err, "error starting vpp (%q)", vi.startupCfg.BinaryPath)
	}

	pid := vi.cmd.Process.Pid
	vi.log = logrus.WithField("pid", pid)
	vi.copyPipeToLog(stdout, "stdout")
	vi.copyPipeToLog(stderr, "stdout")

	// wait for the file to appear so we don't get warnings from govpp
	if err := WaitForFile(socketclient.DefaultSocketName, 100*time.Millisecond, VPP_STARTUP_TIMEOUT); err != nil {
		return errors.Wrap(err, "error waiting for VPP to start")
	}

	conn, conev, err := govpp.AsyncConnect(
		socketclient.DefaultSocketName,
		VPP_MAX_CONNECT_ATTEMPTS,
		VPP_RECONNECT_INTERVAL)

	if err != nil {
		vi.stopVPP()
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
		vi.stopVPP()
		return errors.Wrap(err, "NewAPIChannel")
	}

	go func() {
		defer signal.Stop(sigchldCh)
		for {
			select {
			case <-vi.Context.Done():
			case <-sigchldCh:
				time.Sleep(500 * time.Millisecond)
				var s unix.WaitStatus
				wpid, err := unix.Wait4(pid, &s, unix.WNOHANG, nil)
				if err == nil && wpid == 0 {
					continue
				}
				if err != nil {
					vi.log.WithError(err).Warn("Wait4 error")
				} else {
					vi.log.Info("VPP process has exited")
				}
				vi.cancel()
				return
			case e := <-conev:
				if e.State == core.Failed {
					vi.cancel()
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
	vi.pipeCopyWG.Wait()
	vi.cmd.Wait()
}

func (vi *VPPInstance) closeNamespaces() {
	for _, c := range vi.Captures {
		c.Stop()
	}
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
	vi.log.Debugf(">>> %s", command)
	req := &vpe.CliInband{Cmd: command}
	reply := new(vpe.CliInbandReply)
	if err := vi.apiChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return errors.Wrap(err, "binapi request failed:")
	}
	if reply.Reply != "" {
		vi.log.Debugf("<<< %s", reply.Reply)
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
	vi.log.WithField("nsPath", vi.vppNS.Path()).Info("VPP netns created")

	for _, nsCfg := range vi.cfg.Namespaces {
		ns, err := NewNS(nsCfg.Name)
		if err != nil {
			return errors.Wrapf(err, "NewNS: %s", nsCfg.Name)
		}

		if _, found := vi.namespaces[nsCfg.Name]; found {
			panic("duplicate namespace name")
		}

		if nsCfg.VPPLinkName != "" {
			if err := vi.vppNS.SetupVethPair(nsCfg.VPPLinkName, nil, ns, nsCfg.OtherLinkName, nsCfg.OtherIP); err != nil {
				return errors.Wrap(err, "SetupVethPair (client)")
			}

			for _, rcfg := range nsCfg.NSRoutes {
				if err := ns.AddRoute(rcfg.Dst, rcfg.Gw); err != nil {
					return errors.Wrapf(err, "route for ns %s", nsCfg.Name)
				}
			}
			vi.log.WithFields(logrus.Fields{
				"netns":   nsCfg.Name,
				"nsPath":  ns.Path(),
				"VPPIP":   *nsCfg.VPPIP,
				"OtherIP": *nsCfg.OtherIP,
			}).Info("netns created")
		} else {
			vi.log.WithFields(logrus.Fields{
				"netns":   nsCfg.Name,
				"nsPath":  ns.Path(),
				"OtherIP": *nsCfg.OtherIP,
			}).Info("netns created")
		}

		vi.namespaces[nsCfg.Name] = ns
	}

	return nil
}

func (vi *VPPInstance) StartCapture() error {
	for _, nsCfg := range vi.cfg.Namespaces {
		ns, found := vi.namespaces[nsCfg.Name]
		if !found {
			panic("bad namespace name: " + nsCfg.Name)
		}
		captureCfg := CaptureConfig{
			Iface: nsCfg.VPPLinkName,
			// FIXME: store pcaps to the specified location not /tmp
			PCAPPath: fmt.Sprintf("/tmp/%s.pcap", nsCfg.OtherLinkName),
			Snaplen:  0,
			TargetNS: vi.vppNS,
		}
		if nsCfg.VPPLinkName == "" {
			captureCfg.Iface = nsCfg.OtherLinkName
			captureCfg.TargetNS = ns
		}
		if nsCfg.L3Capture {
			if nsCfg.OtherIP.IP.To4() == nil {
				captureCfg.LayerType = "IPv6"
			} else {
				captureCfg.LayerType = "IPv4"
			}
		}
		c := NewCapture(captureCfg)
		if err := c.Start(); err != nil {
			return errors.Wrapf(err, "capture for %s (link %s)", nsCfg.Name, captureCfg.Iface)
		}
		vi.Captures[nsCfg.Name] = c
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
	if nsCfg.SkipVPPConfig {
		return nil
	}

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

func (vi *VPPInstance) copyPipeToLog(pipe io.ReadCloser, what string) {
	log := vi.log.WithField("what", what)
	vi.pipeCopyWG.Add(1)

	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			log.Infof("VPP: %s", scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			log.WithError(err).Error("log scanner error")
		}

		if err := pipe.Close(); err != nil {
			log.WithError(err).Error("error closing the pipe")
		}
		vi.pipeCopyWG.Done()
	}()
}

// TODO: !!! separate log and socket paths for VPPs !!!
