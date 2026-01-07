// vpp.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2021 Travelping GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"

	ps "github.com/mitchellh/go-ps"
	"github.com/sirupsen/logrus"
	"go.fd.io/govpp"
	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/socketclient"
	"go.fd.io/govpp/adapter/statsclient"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/vlib"
	"go.fd.io/govpp/core"
	"golang.org/x/sys/unix"
	"gopkg.in/tomb.v2"

	"github.com/travelping/upg-vpp/test/e2e/binapi/ip_types"
	"github.com/travelping/upg-vpp/test/e2e/binapi/ipfix_export"
	"github.com/travelping/upg-vpp/test/e2e/binapi/upf"
	"github.com/travelping/upg-vpp/test/e2e/network"
	"github.com/travelping/upg-vpp/test/e2e/util"
)

const (
	VPP_MAX_CONNECT_ATTEMPTS = 10
	VPP_RECONNECT_INTERVAL   = time.Second
	// the startup can get quite slow if too many tests are
	// run in parallel without enough CPU cores available
	VPP_STARTUP_TIMEOUT           = 60 * time.Second
	VPP_STARTUP_TIMEOUT_GDBSERVER = 600 * time.Second
	VPP_REPLY_TIMEOUT             = 5 * time.Second
	NSENTER_CMD                   = "nsenter"
	DISPATCH_TRACE_FILENAME       = "dispatch-trace.pcap"
)

type VPPNetworkNamespace struct {
	Name          string
	VPPMac        net.HardwareAddr
	VPPIP         *net.IPNet
	OtherIP       *net.IPNet
	VPPLinkName   string
	Table         int
	SkipVPPConfig bool
	L3Capture     bool
	MTU           int
	Placement     int
}

type NWIConfig struct {
	Name                   string
	Table                  int
	TxTable                int
	IPFIXPolicy            string
	IPFIXReportingInterval int
	ObservationDomainId    int
	ObservationDomainName  string
	ObservationPointId     int
	GetIPFIXCollectorIP    func() net.IP
}

type IPFIXExporterConfig struct {
	GetCollectorIP func() net.IP
	GetSrcIP       func() net.IP
	Port           int
	VRF            int
}

type VPPConfig struct {
	BaseDir        string
	InitCommands   []string
	Namespaces     []VPPNetworkNamespace
	IPFIXExporters []IPFIXExporterConfig
	NWIs           []NWIConfig
	SetupCommands  []string
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
			if ns.VPPLinkName == "" {
				panic("empty VPPLinkName for namespace " + namespace)
			}
			return ns.VPPLinkName
		}
	}

	panic("No network namespace: " + namespace)
}

type VPPInstance struct {
	cfg                   VPPConfig
	startupCfg            VPPStartupConfig
	conn                  *core.Connection
	ApiChannel            api.Channel
	cmd                   *exec.Cmd
	vppNS                 *network.NetNS
	namespaces            map[string]*network.NetNS
	Captures              map[string]*network.Capture
	log                   *logrus.Entry
	pipeCopyWG            sync.WaitGroup
	t                     tomb.Tomb
	dispatchTraceFileName string
	tapIndex              int
	statsClient           *statsclient.StatsClient
}

func NewVPPInstance(cfg VPPConfig) *VPPInstance {
	if cfg.BaseDir == "" {
		panic("must specify BaseDir")
	}
	var startupCfg VPPStartupConfig
	startupCfg.SetFromEnv()
	return &VPPInstance{
		cfg:        cfg,
		startupCfg: startupCfg,
		namespaces: make(map[string]*network.NetNS),
		Captures:   make(map[string]*network.Capture),
		log:        logrus.NewEntry(logrus.StandardLogger()),
	}
}

func (vi *VPPInstance) Context(parent context.Context) context.Context {
	return vi.t.Context(parent)
}

func (vi *VPPInstance) GetNS(name string) *network.NetNS {
	ns, ok := vi.namespaces[name]
	if !ok {
		log.Panicf("namespace %q not found", name)
	}
	return ns
}

func (vi *VPPInstance) VerifyVPPAlive() error {
	if _, err := vi.Ctl("show version"); err != nil {
		return errors.Wrap(err, "VPP is not alive: error executing 'show upf version'")
	}

	return nil
}

func (vi *VPPInstance) vppFilePath(name string) string {
	return filepath.Join(vi.cfg.BaseDir, name)
}

func (vi *VPPInstance) writeVPPFile(name, content string) (string, error) {
	p := vi.vppFilePath(name)
	if err := ioutil.WriteFile(p, []byte(content), 0666); err != nil {
		return "", errors.Wrapf(err, "error writing %q", name)
	}

	return p, nil
}

func (vi *VPPInstance) prepareCommand() (*exec.Cmd, error) {
	vi.startupCfg.CLISock = vi.vppFilePath("cli.sock")
	vi.startupCfg.APISock = vi.vppFilePath("api.sock")
	vi.startupCfg.StatsSock = vi.vppFilePath("stats.sock")
	vi.startupCfg.VPPLog = vi.vppFilePath("vpp.log")

	vi.startupCfg.MainCore = Cores[0]
	if vi.startupCfg.Multicore {
		vi.startupCfg.WorkerCore = Cores[1]
	}

	startupFile, err := vi.writeVPPFile("startup.conf", vi.startupCfg.Get())
	if err != nil {
		return nil, errors.Wrap(err, "error writing startup file")
	}

	args := []string{"--net=" + vi.vppNS.Path()}
	if vi.startupCfg.UseGDBServer {
		vi.log.Infof("started gdbserver, please attach with\n"+
			"%s %s gdb -ex 'target remote localhost:%d'\n"+
			"and type 'continue' to stat",
			NSENTER_CMD, strings.Join(args, " "),
			vi.startupCfg.GDBServerPort)
		args = append(args, "gdbserver", fmt.Sprintf("localhost:%d", vi.startupCfg.GDBServerPort))
	} else if vi.startupCfg.UseGDB {
		gdbCmdsFile, err := vi.writeVPPFile("gdbcmds",
			`
handle SIGPIPE nostop noprint ignore
handle SIGUSR1 nostop print pass
handle SIGINT stop print pass
r
thread apply all bt full 30
`)
		if err != nil {
			return nil, errors.Wrap(err, "error writing gdbcmds")
		}

		args = append(args, "gdb", "--batch", "-x", gdbCmdsFile, "--args")
	}
	args = append(args, vi.startupCfg.BinaryPath, "-c", startupFile)

	return exec.Command(NSENTER_CMD, args...), nil
}

func (vi *VPPInstance) InterruptVPP() {
	if vi.cmd == nil || vi.cmd.ProcessState != nil {
		vi.log.Info("can't interrupt VPP as it is not running")
		return
	}

	if !vi.startupCfg.UseGDB || vi.t.Err() != nil {
		// try to get stacktrace if there an error
		vi.cmd.Process.Signal(syscall.SIGINT)
		return
	}

	pl, err := ps.Processes()
	if err != nil {
		vi.log.Error(err, "error listing processes")
	}
	for _, proc := range pl {
		if proc.PPid() == vi.cmd.Process.Pid {
			vi.log.Info("forcibly interrupting VPP process",
				"pid", proc.Pid(), "executable", proc.Executable())
			if err := syscall.Kill(proc.Pid(), syscall.SIGINT); err != nil {
				vi.log.Error(err, "error interrupting VPP process")
			}
		}
	}
}

func (vi *VPPInstance) cleanupSharedMemoryFiles() {
	// these files can cause vpp to fail with different _svm_* corruption errors
	if vi.startupCfg.APIPrefix != "" {
		os.Remove(path.Join("/dev/shm/", vi.startupCfg.APIPrefix+"-global_vm"))
		os.Remove(path.Join("/dev/shm/", vi.startupCfg.APIPrefix+"-vpe-api"))
	}
}

func (vi *VPPInstance) StartVPP() error {
	vi.log.WithFields(logrus.Fields{
		"cliSocket": vi.startupCfg.CLISock,
		"apiSocket": vi.startupCfg.APISock,
	}).Info("starting VPP")

	vi.cleanupSharedMemoryFiles()

	var err error
	vi.cmd, err = vi.prepareCommand()
	if err != nil {
		return err
	}

	stdout, err := vi.cmd.StdoutPipe()
	if err != nil {
		return errors.Wrap(err, "StdoutPipe")
	}
	stderr, err := vi.cmd.StderrPipe()
	if err != nil {
		return errors.Wrap(err, "StderrPipe")
	}

	vi.cmd.Env = []string{
		"ASAN_OPTIONS=debug=0:verbosity=0:detect_invalid_pointer_pairs=2",
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
	timeout := VPP_STARTUP_TIMEOUT
	if vi.startupCfg.UseGDBServer {
		timeout = VPP_STARTUP_TIMEOUT_GDBSERVER
	}
	if err := waitForFile(vi.startupCfg.APISock, 100*time.Millisecond, timeout); err != nil {
		vi.killVPP()
		return errors.Wrap(err, "error waiting for VPP to start")
	}

	conn, conev, err := govpp.AsyncConnect(
		vi.startupCfg.APISock,
		VPP_MAX_CONNECT_ATTEMPTS,
		VPP_RECONNECT_INTERVAL)

	if err != nil {
		vi.killVPP()
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
	vi.ApiChannel, err = conn.NewAPIChannel()
	if err != nil {
		vi.killVPP()
		vi.conn.Disconnect()
		vi.conn = nil
		return errors.Wrap(err, "NewAPIChannel")
	}
	vi.ApiChannel.SetReplyTimeout(VPP_REPLY_TIMEOUT)

	vi.t.Go(func() error { return vi.run(sigchldCh, conev) })

	return nil
}

func (vi *VPPInstance) killVPP() {
	if vi.t.Err() != nil {
		// try to get stacktrace from gdb
		vi.cmd.Process.Signal(syscall.SIGINT)
		time.Sleep(500 * time.Millisecond)
	}
	vi.cmd.Process.Kill()
	vi.pipeCopyWG.Wait()
	vi.cmd.Wait()
}

func (vi *VPPInstance) run(sigchldCh chan os.Signal, conev chan core.ConnectionEvent) error {
	pid := vi.cmd.Process.Pid
	defer signal.Stop(sigchldCh)
	for {
		select {
		case <-vi.t.Dying():
			vi.killVPP()
			return nil
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
				vi.pipeCopyWG.Wait()
				vi.log.Info("VPP process has exited")
			}
			return nil
		case e := <-conev:
			if e.State == core.Failed || e.State == core.NotResponding {
				vi.log.Errorf("VPP conn failed / VPP not responding, interrupting the VPP process")
				vi.InterruptVPP()
				return errors.New("VPP API connection failed")
			}
		}
	}
}

func (vi *VPPInstance) stopVPP(fail bool) error {
	if vi.ApiChannel != nil {
		vi.ApiChannel.Close()
		vi.ApiChannel = nil
	}

	if vi.conn != nil {
		vi.conn.Disconnect()
		vi.conn = nil
	}

	var reason error = nil
	if fail {
		reason = errors.New("test fail")
	}
	vi.t.Kill(reason)
	return vi.t.Wait()
}

func (vi *VPPInstance) closeNamespaces() {
	// Stopping captures may block for a few seconds, so let's
	// stop them in parallel and wait for their Stop() calls to
	// complete
	var wg sync.WaitGroup
	for _, c := range vi.Captures {
		wg.Add(1)
		go func(cap *network.Capture) {
			cap.Stop()
			wg.Done()
		}(c)
	}
	wg.Wait()
	for _, ns := range vi.namespaces {
		ns.Close()
	}
	if vi.vppNS != nil {
		vi.vppNS.Close()
		vi.vppNS = nil
	}
	vi.namespaces = nil
}

func (vi *VPPInstance) stopDispatchTrace() {
	if vi.dispatchTraceFileName == "" {
		return
	}

	if _, err := vi.Ctl("pcap dispatch trace off"); err != nil {
		vi.log.WithError(err).Error("error writing dispatch trace")
	}

	targetPath := vi.vppFilePath(DISPATCH_TRACE_FILENAME)
	if err := os.Rename(vi.dispatchTraceFileName, targetPath); err != nil {
		vi.log.WithError(err).Error("error moving dispatch trace file")
	}
}

func (vi *VPPInstance) TearDown(fail bool) {
	if vi.startupCfg.Trace {
		vi.Ctl("show trace")
	}
	if vi.statsClient != nil {
		vi.statsClient.Disconnect()
		vi.statsClient = nil
	}
	vi.stopDispatchTrace()
	if err := vi.stopVPP(fail); err != nil {
		vi.log.WithError(err).Error("error stopping VPP")
	}
	vi.closeNamespaces()
	vi.cleanupSharedMemoryFiles()
}

func (vi *VPPInstance) Ctl(format string, args ...interface{}) (string, error) {
	command := fmt.Sprintf(format, args...)
	vi.log.Debugf(">>> %s", command)
	req := &vlib.CliInband{Cmd: command}
	reply := new(vlib.CliInbandReply)
	if err := vi.ApiChannel.SendRequest(req).ReceiveReply(reply); err != nil {
		return "", errors.Wrap(err, "binapi request failed:")
	}
	if reply.Reply != "" {
		vi.log.Debugf("<<< %s", reply.Reply)
	}
	return reply.Reply, nil
}

func (vi *VPPInstance) DumpStats(stat string) ([]adapter.StatEntry, error) {
	if vi.statsClient == nil {
		vi.statsClient = statsclient.NewStatsClient(vi.startupCfg.StatsSock)
		if err := vi.statsClient.Connect(); err != nil {
			return nil, errors.Wrapf(err, "failed to connect stats client to %q", vi.startupCfg.StatsSock)
		}
	}
	return vi.statsClient.DumpStats(stat)
}

func (vi *VPPInstance) setupLoopback() error {
	_, ipNet, _ := net.ParseCIDR("127.0.0.1/8")

	if err := vi.vppNS.AddAddress("lo", ipNet); err != nil {
		return errors.Wrap(err, "error adding address to lo")
	}

	if err := vi.vppNS.SetLinkUp("lo"); err != nil {
		return errors.Wrap(err, "error briging up the loopback interface")
	}

	return nil
}

func (vi *VPPInstance) SetupNamespaces() error {
	var err error

	vi.vppNS, err = network.NewNS("vpp")
	if err != nil {
		vi.closeNamespaces()
		return errors.Wrap(err, "VppNS")
	}

	if vi.startupCfg.UseGDBServer {
		// need localhost for gdbserver
		if err := vi.setupLoopback(); err != nil {
			return err
		}
	}

	vi.log.WithField("nsPath", vi.vppNS.Path()).Info("VPP netns created")

	for _, nsCfg := range vi.cfg.Namespaces {
		ns, err := network.NewNS(nsCfg.Name)
		if err != nil {
			return errors.Wrapf(err, "NewNS: %s", nsCfg.Name)
		}

		if _, found := vi.namespaces[nsCfg.Name]; found {
			panic("duplicate namespace name")
		}

		vi.log.WithFields(logrus.Fields{
			"netns":   nsCfg.Name,
			"nsPath":  ns.Path(),
			"OtherIP": *nsCfg.OtherIP,
		}).Info("netns created")

		if nsCfg.OtherIP != nil && nsCfg.OtherIP.IP.To4() == nil {
			ns.SetIPv6()
		}

		vi.namespaces[nsCfg.Name] = ns
	}

	return nil
}

func (vi *VPPInstance) SetupRoutes() error {
	for _, nsCfg := range vi.cfg.Namespaces {
		ns, found := vi.namespaces[nsCfg.Name]
		if !found {
			return errors.Errorf("namespace not found: " + nsCfg.Name)
		}

		if nsCfg.OtherIP != nil && !nsCfg.SkipVPPConfig {
			// we need to add OtherIP first, to setup route via it
			// we add this address using /32 suffix, since we do not require any routing
			ipNet := net.IPNet{
				IP: netip.MustParseAddr(nsCfg.OtherIP.IP.String()).AsSlice(),
			}
			ipNet.Mask = make(net.IPMask, len(ipNet.IP))
			for i := range ipNet.Mask {
				ipNet.Mask[i] = 0xff
			}

			if nsCfg.OtherIP.IP.To4() == nil {
				if err := ns.Do(func() error {
					// https://unix.stackexchange.com/questions/293629/let-ifconfig-wait-for-ipv6-address-to-not-be-tentative
					if _, err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.dad_transmits=0", nsCfg.VPPLinkName)).CombinedOutput(); err != nil {
						return err
					}
					if _, err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.accept_dad=0", nsCfg.VPPLinkName)).CombinedOutput(); err != nil {
						return err
					}
					return nil
				}); err != nil {
					return errors.Wrapf(err, "failed to disable ipv6 DAD for %s", nsCfg.VPPLinkName)
				}
			}

			if err := ns.AddAddress(nsCfg.VPPLinkName, &ipNet); err != nil {
				return errors.Wrapf(err, "addr for interface %s", nsCfg.Name)
			}

			if nsCfg.OtherIP.IP.To4() == nil { // briefly wait for tentative transition
				time.Sleep(50 * time.Millisecond)
			}

			if nsCfg.VPPIP != nil && nsCfg.VPPIP.IP != nil {
				if err := ns.AddRouteLink(nsCfg.VPPLinkName, &net.IPNet{
					IP:   nsCfg.VPPIP.IP,
					Mask: ipNet.Mask,
				}, ipNet.IP); err != nil {
					return errors.Wrapf(err, "route for local scope %s", nsCfg.Name)
				}

				// Our default route is always VPPIP, since we have no other interconnection
				if err := ns.AddRoute(nil, nsCfg.VPPIP.IP); err != nil {
					return errors.Wrapf(err, "route for ns %s", nsCfg.Name)
				}
			}
		}

		// Now we force routing of traffic through network, even if this is localhost traffic
		// For case when we ping addresses in same namespace, but want to route it via gateway
		// instead of resolving via local table
		ns.Do(func() error {
			cmds := []string{
				// change local table rule preference from 0 to 1
				"ip -4 rule add from all lookup local pref 1",
				"ip -6 rule add from all lookup local pref 1",
				"ip -4 rule del from all lookup local pref 0",
				"ip -6 rule del from all lookup local pref 0",
				// because we want to add our lookup in default table rule with higher priority
				// for cases when traffic came from local interface
				"ip -4 rule add from all iif lo lookup main pref 0",
				"ip -6 rule add from all iif lo lookup main pref 0",

				// enable forwarding
				"sysctl -w net.ipv4.ip_forward=1",
				"sysctl -w net.ipv6.conf.all.forwarding=1",
			}
			if _, err := exec.Command("sh", "-c", strings.Join(cmds, " && ")).CombinedOutput(); err != nil {
				return err
			}
			return nil
		})
	}
	return nil
}

func (vi *VPPInstance) StartCapture() error {
	for _, nsCfg := range vi.cfg.Namespaces {
		ns, found := vi.namespaces[nsCfg.Name]
		if !found {
			panic("bad namespace name: " + nsCfg.Name)
		}
		captureCfg := network.CaptureConfig{
			Iface: nsCfg.VPPLinkName,
			// FIXME: store pcaps to the specified location not /tmp
			PCAPPath: filepath.Join(vi.cfg.BaseDir, fmt.Sprintf("%s.pcap", nsCfg.VPPLinkName)),
			Snaplen:  0,
			TargetNS: vi.vppNS,
		}

		captureCfg.Iface = nsCfg.VPPLinkName
		captureCfg.TargetNS = ns

		if nsCfg.L3Capture {
			if nsCfg.OtherIP.IP.To4() == nil {
				captureCfg.LayerType = "IPv6"
			} else {
				captureCfg.LayerType = "IPv4"
			}
		}
		c := network.NewCapture(captureCfg)
		if err := c.Start(); err != nil {
			return errors.Wrapf(err, "capture for %s (link %s)", nsCfg.Name, captureCfg.Iface)
		}
		vi.Captures[nsCfg.Name] = c
	}

	return nil
}

func (vi *VPPInstance) runCmds(cmds ...string) error {
	for _, cmd := range cmds {
		canFail := false
		if strings.HasPrefix(cmd, "?") {
			cmd = cmd[1:]
			canFail = true
		}
		if _, err := vi.Ctl("%s", cmd); err != nil {
			if canFail {
				vi.log.WithField("cmd", cmd).WithError(err).Warn("command failed")
			} else {
				return errors.Wrapf(err, "vpp command %q", cmd)
			}
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
	mtu := nsCfg.MTU
	if mtu == 0 {
		mtu = vi.startupCfg.DefaultMTU()
	}
	ns, found := vi.namespaces[nsCfg.Name]
	if !found {
		panic("namespace not found: " + nsCfg.Name)
	}
	vi.tapIndex += 1
	hostAddr := ""

	cmds = append(cmds, fmt.Sprintf("create tap id %d host-ns %s%s host-if-name %s rx-ring-size 1024 tx-ring-size 1024 persist attach", vi.tapIndex, ns.Path(), hostAddr, nsCfg.VPPLinkName))
	cmds = append(cmds, fmt.Sprintf("set interface name tap%d %s", vi.tapIndex, nsCfg.VPPLinkName))

	if vi.startupCfg.Multicore {
		placement := "main"
		if nsCfg.Placement >= 0 {
			placement = fmt.Sprintf("worker %d", nsCfg.Placement)
		}
		cmds = append(cmds,
			fmt.Sprintf("set interface rx-placement %s %s",
				nsCfg.VPPLinkName, placement))
	}

	if vi.startupCfg.InterruptMode {
		cmds = append(cmds,
			fmt.Sprintf("set interface rx-mode %s interrupt", nsCfg.VPPLinkName))
	}

	return append(cmds,
		// fmt.Sprintf("set interface mac address %s %s", nsCfg.VPPLinkName, nsCfg.VPPMac),
		fmt.Sprintf("set interface %s table %s %d", ipCmd, nsCfg.VPPLinkName, nsCfg.Table),
		fmt.Sprintf("set interface ip address %s %s", nsCfg.VPPLinkName, nsCfg.VPPIP),
		fmt.Sprintf("set interface state %s up", nsCfg.VPPLinkName),
		fmt.Sprintf("set interface mtu %d %s", mtu, nsCfg.VPPLinkName),
	)
}

func (vi *VPPInstance) setupDispatchTrace() error {
	tmpFile, err := ioutil.TempFile("/tmp", "vppcapture-*")
	if err != nil {
		return errors.Wrap(err, "error creating vppcapture temp file")
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return errors.Wrap(err, "error creating vppcapture temp file (closing)")
	}

	_, err = vi.Ctl("pcap dispatch trace on max 100000 file %s buffer-trace virtio-input 100", filepath.Base(tmpFile.Name()))
	if err != nil {
		return errors.Wrap(err, "error turning on the dispatch trace")
	}

	vi.dispatchTraceFileName = tmpFile.Name()
	return nil
}

func (vi *VPPInstance) setupExporters() error {
	for _, expCfg := range vi.cfg.IPFIXExporters {
		req := &ipfix_export.IpfixExporterCreateDelete{
			IsCreate:         true,
			CollectorAddress: ip_types.AddressFromIP(expCfg.GetCollectorIP()),
			CollectorPort:    uint16(expCfg.Port),
			SrcAddress:       ip_types.AddressFromIP(expCfg.GetSrcIP()),
			VrfID:            uint32(expCfg.VRF),
			PathMtu:          1450,
			TemplateInterval: 1,
		}

		reply := &ipfix_export.IpfixExporterCreateDeleteReply{}
		if err := vi.ApiChannel.SendRequest(req).ReceiveReply(reply); err != nil {
			return errors.Wrap(err, "ipfix_exporter_create_delete error")
		}
	}

	return nil
}

func (vi *VPPInstance) setupNWIs() error {
	for _, nwiCfg := range vi.cfg.NWIs {
		if nwiCfg.TxTable == 0 {
			nwiCfg.TxTable = nwiCfg.Table
		}

		req := &upf.UpfNwiAddDel{
			Nwi:                 util.EncodeFQDN(nwiCfg.Name),
			IP4TableID:          uint32(nwiCfg.Table),
			IP6TableID:          uint32(nwiCfg.Table),
			TxIP4TableID:        uint32(nwiCfg.TxTable),
			TxIP6TableID:        uint32(nwiCfg.TxTable),
			IpfixReportInterval: uint32(nwiCfg.IPFIXReportingInterval),
			ObservationDomainID: uint32(nwiCfg.ObservationDomainId),
			ObservationPointID:  uint64(nwiCfg.ObservationPointId),
			Add:                 1,
		}

		if nwiCfg.ObservationDomainName != "" {
			req.ObservationDomainName = []byte(nwiCfg.ObservationDomainName)
		}

		if nwiCfg.IPFIXPolicy != "" {
			req.IpfixPolicy = []byte(nwiCfg.IPFIXPolicy)
		}

		if nwiCfg.GetIPFIXCollectorIP != nil {
			req.IpfixCollectorIP = ip_types.AddressFromIP(nwiCfg.GetIPFIXCollectorIP())
		}

		reply := &upf.UpfNwiAddDelReply{}
		if err := vi.ApiChannel.SendRequest(req).ReceiveReply(reply); err != nil {
			return errors.Wrap(err, "upf_nwi_add_del binapi error")
		}
	}

	return nil
}

func (vi *VPPInstance) Configure() error {
	if vi.startupCfg.DispatchTrace {
		if err := vi.setupDispatchTrace(); err != nil {
			return err
		}
	}

	initialCmds := []string{
		"upf flow config max-flows-per-worker 10000", // reduce memory pool size for tests
		"upf pfcp server set fifo-size 512",
		// sometimes crashes due to bug in VPP, but useful to debug tcp proxy stuff anyways
		// fmt.Sprintf("upf post-mortem enable elog_limit %d", vi.startupCfg.PostMortemElogLimit),
	}
	initialCmds = append(initialCmds, vi.cfg.InitCommands...)
	for _, nsCfg := range vi.cfg.Namespaces {
		initialCmds = append(initialCmds, vi.interfaceCmds(nsCfg)...)
	}

	if err := vi.runCmds(initialCmds...); err != nil {
		// here pfcp specific errors will mean that plugin was not loaded
		res, err2 := vi.Ctl("show logging")
		if err2 != nil {
			return err // return original error
		}
		if strings.Contains(res, "/usr/lib/x86_64-linux-gnu/vpp_plugins/upf_plugin.so") {
			parts1 := strings.SplitN(res, "/usr/lib/x86_64-linux-gnu/vpp_plugins/upf_plugin.so", 2)
			parts2 := strings.SplitN(parts1[1], "\n", 2)
			return errors.Errorf("error loading upf plugin: %q", parts2[0])
		}
		log.Printf("%s", res)

		return err
	}

	if err := vi.setupExporters(); err != nil {
		return err
	}

	if err := vi.setupNWIs(); err != nil {
		return err
	}

	cmds := vi.cfg.SetupCommands
	if vi.startupCfg.Trace {
		cmds = append(cmds, "trace add virtio-input 10000")
	}
	return vi.runCmds(cmds...)
}

func (vi *VPPInstance) copyPipeToLog(pipe io.ReadCloser, what string) {
	log := vi.log.WithField("what", what)
	vi.pipeCopyWG.Add(1)

	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			// TODO: TODO: TODO: restore
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

func waitForFile(path string, interval, timeout time.Duration) error {
	timeoutCh := time.After(timeout)
	for {
		switch _, err := os.Stat(path); {
		case err == nil:
			return nil
		case os.IsNotExist(err):
			// ok, let's wait a bit more
		default:
			return errors.Wrapf(err, "error waiting for %q", path)
		}
		select {
		case <-time.After(interval):
			continue
		case <-timeoutCh:
			return errors.Errorf("timed out waiting for %q", path)
		}
	}
}

func init() {
	// VPP may be slow responding to the health probe
	// when there's a lot of output
	core.HealthCheckReplyTimeout = 500 * time.Millisecond
	core.HealthCheckThreshold = 10
}
