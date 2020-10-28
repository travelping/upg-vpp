package framework

import (
	"time"

	"github.com/onsi/ginkgo"
)

var (
	DefaultUEIP     = MustParseIP("10.0.1.3")
	DefaultServerIP = MustParseIP("10.0.2.3")
)

type Framework struct {
	VPPCfg  *VPPConfig
	VPP     *VPPInstance
	PFCPCfg *PFCPConfig
	PFCP    *PFCPConnection
}

func NewDefaultFramework() *Framework {
	return NewFramework(defaultVPPConfig(), defaultPFCPConfig())
}

func NewFramework(vppCfg *VPPConfig, pfcpCfg *PFCPConfig) *Framework {
	f := &Framework{
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
	ExpectNoError(f.VPP.StartVPP())
	ExpectNoError(f.VPP.Ctl("show version"))
	ExpectNoError(f.VPP.Configure())
	ExpectNoError(f.VPP.VerifyVPPAlive())

	if f.PFCPCfg != nil {
		f.PFCPCfg.Namespace = f.VPP.GetNS("cp")
		f.PFCP = NewPFCPConnection(*f.PFCPCfg)
		ExpectNoError(f.PFCP.Start(f.VPP.Context))
	}
}

func (f *Framework) AfterEach() {
	if f.VPP != nil {
		ExpectNoError(f.VPP.VerifyVPPAlive())
		if f.PFCP != nil {
			// FIXME: we need to make sure all PFCP packets are recorded
			<-time.After(time.Second)
			ExpectNoError(f.PFCP.Stop(f.VPP.Context))
			f.PFCP = nil
		}
		f.VPP.TearDown()
		f.VPP = nil
	}
}

func defaultVPPConfig() *VPPConfig {
	return &VPPConfig{
		Namespaces: []VPPNetworkNamespace{
			{
				Name:          "cp",
				VPPMac:        MustParseMAC("fa:8a:78:4d:5b:5b"),
				VPPIP:         MustParseIPNet("10.0.0.2/24"),
				OtherIP:       MustParseIPNet("10.0.0.3/24"),
				VPPLinkName:   "cp0",
				OtherLinkName: "cp1",
				Table:         0,
			},
			{
				Name:          "access",
				VPPMac:        MustParseMAC("fa:8a:78:4d:18:01"),
				VPPIP:         MustParseIPNet("10.0.1.2/24"),
				OtherIP:       MustParseIPNet("10.0.1.3/24"),
				VPPLinkName:   "access0",
				OtherLinkName: "access1",
				Table:         100,
				NSRoutes: []RouteConfig{
					{
						Gw: MustParseIP("10.0.1.2"),
					},
				},
			},
			{
				Name:          "sgi",
				VPPMac:        MustParseMAC("fa:8a:78:4d:19:01"),
				VPPIP:         MustParseIPNet("10.0.2.2/24"),
				OtherIP:       MustParseIPNet("10.0.2.3/24"),
				VPPLinkName:   "sgi0",
				OtherLinkName: "sgi1",
				Table:         200,
				NSRoutes: []RouteConfig{
					{
						Dst: MustParseIPNet("10.0.1.0/24"),
						Gw:  MustParseIP("10.0.2.2"),
					},
				},
			},
		},
		SetupCommands: []string{
			"upf nwi name cp vrf 0",
			"upf nwi name access vrf 100",
			"upf nwi name sgi vrf 200",
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			// NOTE: "ip6" instead of "ip4" for IPv6
			"upf tdf ul table vrf 100 ip4 table-id 1001",
			// NOTE: "ip6" instead of "ip4" for IPv6
			"upf tdf ul enable ip4 host-access0",
			// NOTE: both IP and subnet (ip4 or ipv6) should be variable below
			// For IPv6, ::/0 should be used as the subnet
			"ip route add 0.0.0.0/0 table 200 via 10.0.2.3 host-sgi0",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver-.*",
			// "set upf proxy mss 1250"
		},
	}
}

func defaultPFCPConfig() *PFCPConfig {
	return &PFCPConfig{
		UNodeIP: MustParseIP("10.0.0.2"),
		NodeID:  "pfcpstub",
		UEIP:    DefaultUEIP,
	}
}
