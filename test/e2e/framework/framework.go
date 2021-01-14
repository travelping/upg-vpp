package framework

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/pfcp"
	"github.com/travelping/upg-vpp/test/e2e/sgw"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

const (
	TEIDPGWs5u      = 1000000000
	TEIDSGWs5u      = 1000000001
	ProxyAccessTEID = 1000000002
	ProxyCoreTEID   = 1000000003
)

var artifactsDir string

func SetArtifactsDirectory(dir string) {
	artifactsDir = dir
}

type Framework struct {
	Mode              UPGMode
	IPMode            UPGIPMode
	VPPCfg            *vpp.VPPConfig
	VPP               *vpp.VPPInstance
	PFCPCfg           *pfcp.PFCPConfig
	PFCP              *pfcp.PFCPConnection
	GTPUs             []*GTPU
	Context           context.Context
	GTPUMTU           int
	TPDUHook          TPDUHook
	numExtraCNodeIPs  uint32
	numExtraUEIPs     uint32
	numExtraServerIPs uint32
}

func NewDefaultFramework(mode UPGMode, ipMode UPGIPMode) *Framework {
	vppCfg := vppConfig(mode, ipMode)
	pfcpCfg := DefaultPFCPConfig(vppCfg)
	return NewFramework(mode, ipMode, &vppCfg, &pfcpCfg)
}

func NewFramework(mode UPGMode, ipMode UPGIPMode, vppCfg *vpp.VPPConfig, pfcpCfg *pfcp.PFCPConfig) *Framework {
	f := &Framework{
		Mode:    mode,
		IPMode:  ipMode,
		VPPCfg:  vppCfg,
		PFCPCfg: pfcpCfg,
	}
	ginkgo.BeforeEach(f.BeforeEach)
	ginkgo.AfterEach(f.AfterEach)
	return f
}

func (f *Framework) BeforeEach() {
	// TODO: forced cleanup for Ctrl-C
	// https://github.com/kubernetes/kubernetes/blob/84096f02e9ecb1dd596d3e05b56238485e4ba051/test/e2e/framework/framework.go#L184-L168
	f.numExtraCNodeIPs = 0
	f.numExtraUEIPs = 0
	d, err := ioutil.TempDir("", "upgtest")
	ExpectNoError(err)
	f.VPPCfg.BaseDir = d
	f.VPP = vpp.NewVPPInstance(*f.VPPCfg)
	ExpectNoError(f.VPP.SetupNamespaces())
	// do GTP-U setup before we start the captures,
	// as it creates the ue's link
	switch f.Mode {
	case UPGModeNone, UPGModeTDF:
		f.GTPUs = nil
		f.Context = f.VPP.Context(context.Background())
	case UPGModePGW:
		gtpu, err := NewGTPU(GTPUConfig{
			GRXNS:      f.VPP.GetNS("grx"),
			UENS:       f.VPP.GetNS("ue"),
			UEIP:       f.VPPCfg.GetNamespaceAddress("ue").IP,
			SGWIP:      f.VPPCfg.GetNamespaceAddress("grx").IP,
			PGWIP:      f.VPPCfg.GetVPPAddress("grx").IP,
			TEIDPGWs5u: TEIDPGWs5u,
			TEIDSGWs5u: TEIDSGWs5u,
			LinkName:   f.VPPCfg.GetNamespaceLinkName("ue"),
			MTU:        f.GTPUMTU,
			TPDUHook:   f.TPDUHook,
		})
		ExpectNoError(err)
		ExpectNoError(gtpu.Start(f.VPP.Context(context.Background())))
		f.Context = gtpu.Context(context.Background())
		f.GTPUs = []*GTPU{gtpu}
	case UPGModeGTPProxy:
		// For the purpose of GTPUConfig, VPP is always "PGW",
		// "SGW" being the side of the target test namespace
		accessGTPU, err := NewGTPU(GTPUConfig{
			GRXNS:      f.VPP.GetNS("access"),
			UENS:       f.VPP.GetNS("ue"),
			UEIP:       f.VPPCfg.GetNamespaceAddress("ue").IP,
			SGWIP:      f.VPPCfg.GetNamespaceAddress("access").IP,
			PGWIP:      f.VPPCfg.GetVPPAddress("access").IP,
			TEIDPGWs5u: ProxyAccessTEID,
			TEIDSGWs5u: TEIDSGWs5u,
			LinkName:   f.VPPCfg.GetNamespaceLinkName("ue"),
			MTU:        f.GTPUMTU,
			TPDUHook:   f.TPDUHook,
		})
		ExpectNoError(err)
		ExpectNoError(accessGTPU.Start(f.VPP.Context(context.Background())))
		f.Context = accessGTPU.Context(context.Background())

		// "Inverted" GTP-U on the Core side
		// (FIXME: stop using SGW/PGW in the field names here)
		coreGTPU, err := NewGTPU(GTPUConfig{
			GRXNS:      f.VPP.GetNS("core"),
			UENS:       f.VPP.GetNS("srv"),
			UEIP:       f.VPPCfg.GetNamespaceAddress("srv").IP,
			SGWIP:      f.VPPCfg.GetNamespaceAddress("core").IP,
			PGWIP:      f.VPPCfg.GetVPPAddress("core").IP,
			TEIDPGWs5u: ProxyCoreTEID,
			TEIDSGWs5u: TEIDPGWs5u,
			LinkName:   f.VPPCfg.GetNamespaceLinkName("srv"),
			MTU:        f.GTPUMTU,
			TPDUHook:   f.TPDUHook,
		})
		ExpectNoError(err)
		ExpectNoError(coreGTPU.Start(f.VPP.Context(context.Background())))
		f.Context = coreGTPU.Context(f.Context)

		f.GTPUs = []*GTPU{accessGTPU, coreGTPU}
	}
	ExpectNoError(f.VPP.StartCapture())
	ExpectNoError(f.VPP.StartVPP())
	_, err = f.VPP.Ctl("show version")
	ExpectNoError(err)
	ExpectNoError(f.VPP.Configure())
	ExpectNoError(f.VPP.VerifyVPPAlive())

	for _, nsCfg := range f.VPPCfg.Namespaces {
		if nsCfg.VPPIP == nil {
			continue
		}
		f.Ping(nsCfg.Name, nsCfg.VPPIP.IP, 3)
	}

	if f.PFCPCfg != nil {
		f.PFCPCfg.Namespace = f.VPP.GetNS("cp")
		f.PFCP = pfcp.NewPFCPConnection(*f.PFCPCfg)
		ExpectNoError(f.PFCP.Start(f.VPP.Context(context.Background())))
	} else {
		f.PFCP = nil
	}
}

func (f *Framework) Ping(nsName string, ip net.IP, count int) {
	// TODO: use go-ping instead of 'ping'
	ns := f.VPP.GetNS(nsName)
	countArg := strconv.Itoa(count)
	cmd := exec.Command("nsenter", "--net="+ns.Path(), "ping", "-c", countArg, ip.String())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	ExpectNoError(cmd.Run())
}

func (f *Framework) AfterEach() {
	if f.VPP != nil {
		ExpectNoError(f.VPP.VerifyVPPAlive())
		defer func() {
			if f.VPP != nil {
				f.VPP.TearDown()
				f.VPP = nil
			}
		}()

		if f.PFCP != nil {
			// FIXME: we need to make sure all PFCP packets are recorded
			time.Sleep(time.Second)
			ExpectNoError(f.PFCP.Stop())
			f.PFCP = nil
		}

		for _, gtpu := range f.GTPUs {
			ExpectNoError(gtpu.Stop())
		}
		f.GTPUs = nil

		f.VPP.TearDown()
		f.VPP = nil
	}

	if f.VPPCfg != nil && f.VPPCfg.BaseDir != "" {
		if artifactsDir != "" && ginkgo.CurrentGinkgoTestDescription().Failed {
			ExpectNoError(os.MkdirAll(artifactsDir, os.ModePerm))
			/// XXXXXX: use proper test desc
			targetDir := filepath.Join(artifactsDir, toFilename(ginkgo.CurrentGinkgoTestDescription().FullTestText))
			ExpectNoError(os.RemoveAll(targetDir))
			// FIXME
			ExpectNoError(exec.Command("mv", f.VPPCfg.BaseDir, targetDir).Run())
			matches, err := filepath.Glob(filepath.Join(targetDir, "*.sock"))
			ExpectNoError(err)
			for _, filename := range matches {
				os.Remove(filename)
			}
			logrus.WithField("testDir", targetDir).Info("test artifacts for the failed testcase")
		} else if f.VPPCfg.BaseDir != "" {
			ExpectNoError(os.RemoveAll(f.VPPCfg.BaseDir))
		}
	}
}

func (f *Framework) UEIP() net.IP {
	return f.VPPCfg.GetNamespaceAddress("ue").IP
}

func (f *Framework) ServerIP() net.IP {
	if f.Mode == UPGModeGTPProxy {
		return f.VPPCfg.GetNamespaceAddress("srv").IP
	} else {
		return f.VPPCfg.GetNamespaceAddress("sgi").IP
	}
}

func (f *Framework) addIP(nsName string, count *uint32) net.IP {
	mainAddr := f.VPPCfg.GetNamespaceAddress(nsName)
	ipNet := &net.IPNet{
		Mask: mainAddr.Mask,
	}
	if ip4 := mainAddr.IP.To4(); ip4 != nil {
		ipNet.IP = make(net.IP, net.IPv4len)
		copy(ipNet.IP, ip4)
	} else {
		ipNet.IP = make(net.IP, net.IPv6len)
		copy(ipNet.IP, mainAddr.IP)
	}
	*count++
	n := *count
	for p := len(ipNet.IP) - 1; p >= 0 && n > 0; p-- {
		n += uint32(ipNet.IP[p])
		ipNet.IP[p] = byte(n)
		n >>= 8
	}

	linkName := f.VPPCfg.GetNamespaceLinkName(nsName)
	logrus.WithFields(logrus.Fields{
		"linkName": linkName,
		"nsName":   nsName,
		"ipNet":    ipNet,
	}).Trace("adding an IP address")
	ExpectNoError(f.VPP.GetNS(nsName).AddAddress(linkName, ipNet))
	return ipNet.IP
}

func (f *Framework) AddCNodeIP() net.IP {
	return f.addIP("cp", &f.numExtraCNodeIPs)
}

func (f *Framework) AddUEIP() net.IP {
	return f.addIP("ue", &f.numExtraUEIPs)
}

func (f *Framework) AddServerIP() net.IP {
	var serverNSName string
	if f.Mode == UPGModeGTPProxy {
		serverNSName = "srv"
	} else {
		serverNSName = "sgi"
	}
	return f.addIP(serverNSName, &f.numExtraServerIPs)
}

// SlowGTPU returns true if UPG runs in PGW mode, and userspace GTP-U
// tunneling is being used, which may be not fast enough, causing some
// packet drops on GRX<->UE path. In this case, only GRX pcaps should
// be used to validate traffic measurements
func (f *Framework) SlowGTPU() bool {
	return len(f.GTPUs) > 0 && f.GTPUs[0].cfg.gtpuTunnelType() == sgw.SGWGTPUTunnelTypeTun
}

func DefaultPFCPConfig(vppCfg vpp.VPPConfig) pfcp.PFCPConfig {
	return pfcp.PFCPConfig{
		UNodeIP: vppCfg.GetVPPAddress("cp").IP,
		CNodeIP: vppCfg.GetNamespaceAddress("cp").IP,
		NodeID:  "pfcpstub",
	}
}
