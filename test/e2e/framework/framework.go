package framework

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/pfcp"
	"github.com/travelping/upg-vpp/test/e2e/sgw"
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

const (
	TEIDPGWs5u = 1000000000
	TEIDSGWs5u = 1000000001
)

type Framework struct {
	Mode    UPGMode
	IPMode  UPGIPMode
	VPPCfg  *vpp.VPPConfig
	VPP     *vpp.VPPInstance
	PFCPCfg *pfcp.PFCPConfig
	PFCP    *pfcp.PFCPConnection
	GTPU    *GTPU
	Context context.Context
	GTPUMTU int
}

func NewDefaultFramework(mode UPGMode, ipMode UPGIPMode) *Framework {
	vppCfg := vppConfig(mode, ipMode)
	pfcpCfg := defaultPFCPConfig(vppCfg)
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
	d, err := ioutil.TempDir("", "upgtest")
	ExpectNoError(err)
	f.VPPCfg.BaseDir = d
	f.VPP = vpp.NewVPPInstance(*f.VPPCfg)
	ExpectNoError(f.VPP.SetupNamespaces())
	// do GTP-U setup before we start the captures,
	// as it creates the ue's link
	if f.Mode == UPGModePGW {
		var err error
		f.GTPU, err = NewGTPU(GTPUConfig{
			GRXNS:         f.VPP.GetNS("grx"),
			UENS:          f.VPP.GetNS("ue"),
			UEIP:          f.VPPCfg.GetNamespaceAddress("ue").IP,
			SGWGRXIP:      f.VPPCfg.GetNamespaceAddress("grx").IP,
			PGWGRXIP:      f.VPPCfg.GetVPPAddress("grx").IP,
			TEIDPGWs5u:    TEIDPGWs5u,
			TEIDSGWs5u:    TEIDSGWs5u,
			LinkName:      f.VPPCfg.GetNamespaceLinkName("ue"),
			ParentContext: f.VPP.Context,
			MTU:           f.GTPUMTU,
		})
		ExpectNoError(err)
		ExpectNoError(f.GTPU.Start())
		f.Context = f.GTPU.Context
	} else {
		f.GTPU = nil
		f.Context = f.VPP.Context
	}
	ExpectNoError(f.VPP.StartCapture())
	ExpectNoError(f.VPP.StartVPP())
	ExpectNoError(f.VPP.Ctl("show version"))
	ExpectNoError(f.VPP.Configure())
	ExpectNoError(f.VPP.VerifyVPPAlive())

	if f.PFCPCfg != nil {
		f.PFCPCfg.Namespace = f.VPP.GetNS("cp")
		f.PFCP = pfcp.NewPFCPConnection(*f.PFCPCfg)
		ExpectNoError(f.PFCP.Start(f.VPP.Context))
	} else {
		f.PFCP = nil
	}
}

func (f *Framework) AfterEach() {
	if f.VPP != nil {
		ExpectNoError(f.VPP.VerifyVPPAlive())
		defer func() {
			f.VPP.TearDown()
			f.VPP = nil
		}()
		if f.PFCP != nil {
			// FIXME: we need to make sure all PFCP packets are recorded
			time.Sleep(time.Second)
			ExpectNoError(f.PFCP.Stop(f.VPP.Context))
			f.PFCP = nil
		}

		if f.GTPU != nil {
			ExpectNoError(f.GTPU.Stop())
			f.GTPU = nil
		}
	}

	if f.VPPCfg != nil && f.VPPCfg.BaseDir != "" {
		if ginkgo.CurrentGinkgoTestDescription().Failed {
			logrus.WithField("testDir", f.VPPCfg.BaseDir).Info("test artifacts for the failed testcase")
		} else if f.VPPCfg.BaseDir != "" {
			ExpectNoError(os.RemoveAll(f.VPPCfg.BaseDir))
		}
	}
}

func (f *Framework) UEIP() net.IP {
	return f.VPPCfg.GetNamespaceAddress("ue").IP
}

func (f *Framework) ServerIP() net.IP {
	return f.VPPCfg.GetNamespaceAddress("sgi").IP
}

// SlowGTPU returns true if UPG runs in PGW mode, and userspace GTP-U
// tunneling is being used, which may be not fast enough, causing some
// packet drops on GRX<->UE path. In this case, only GRX pcaps should
// be used to validate traffic measurements
func (f *Framework) SlowGTPU() bool {
	return f.Mode == UPGModePGW && f.GTPU.cfg.gtpuTunnelType() == sgw.SGWGTPUTunnelTypeTun
}

func defaultPFCPConfig(vppCfg vpp.VPPConfig) pfcp.PFCPConfig {
	return pfcp.PFCPConfig{
		UNodeIP: vppCfg.GetVPPAddress("cp").IP,
		CNodeIP: vppCfg.GetNamespaceAddress("cp").IP,
		NodeID:  "pfcpstub",
	}
}
