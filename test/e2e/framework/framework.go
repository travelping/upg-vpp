package framework

import (
	"context"
	"net"
	"time"

	"github.com/onsi/ginkgo"

	"github.com/travelping/upg-vpp/test/e2e/sgw"
)

const (
	TEIDPGWs5u = 1000000000
	TEIDSGWs5u = 1000000001
)

type Framework struct {
	Mode    UPGMode
	VPPCfg  *VPPConfig
	VPP     *VPPInstance
	PFCPCfg *PFCPConfig
	PFCP    *PFCPConnection
	GTPU    *GTPU
	Context context.Context
}

func NewDefaultFramework(mode UPGMode) *Framework {
	vppCfg := vppConfig(mode)
	pfcpCfg := defaultPFCPConfig(vppCfg)
	return NewFramework(mode, &vppCfg, &pfcpCfg)
}

func NewFramework(mode UPGMode, vppCfg *VPPConfig, pfcpCfg *PFCPConfig) *Framework {
	f := &Framework{
		Mode:    mode,
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
	f.VPP = NewVPPInstance(*f.VPPCfg)
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
		f.PFCP = NewPFCPConnection(*f.PFCPCfg)
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
	return f.Mode == UPGModePGW && gtpuTunnelType() == sgw.SGWGTPUTunnelTypeTun
}

func defaultPFCPConfig(vppCfg VPPConfig) PFCPConfig {
	return PFCPConfig{
		UNodeIP: vppCfg.GetVPPAddress("cp").IP,
		CNodeIP: vppCfg.GetNamespaceAddress("cp").IP,
		NodeID:  "pfcpstub",
	}
}
