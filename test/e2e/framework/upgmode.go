package framework

type UPGMode int

const (
	UPGModeNone UPGMode = iota
	UPGModePGW
	UPGModeTDF
)

func vppConfig(mode UPGMode) VPPConfig {
	switch mode {
	case UPGModeTDF:
		return tdfVPPConfig()
	case UPGModePGW:
		return pgwVPPConfig()
	default:
		panic("bad UPGMode")
	}
}

func tdfVPPConfig() VPPConfig {
	return VPPConfig{
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
				Name:          "ue",
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
			// TODO: make stitching optional and verify it
			"set upf proxy mss 1250",
		},
	}
}

func pgwVPPConfig() VPPConfig {
	return VPPConfig{
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
				Name:          "ue",
				OtherIP:       MustParseIPNet("10.0.1.3/24"),
				OtherLinkName: "access",
				SkipVPPConfig: true,
				// using L3 capture because of tun
				// (no Ethernet headers)
				L3Capture: true,
				// the default route is added by gtpu (sgw) code here
			},
			{
				Name:          "grx",
				VPPMac:        MustParseMAC("fa:8a:78:4d:42:01"),
				VPPIP:         MustParseIPNet("10.0.3.2/24"),
				OtherIP:       MustParseIPNet("10.0.3.3/24"),
				VPPLinkName:   "grx0",
				OtherLinkName: "grx1",
				Table:         100,
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
			"upf nwi name epc vrf 100",
			"upf nwi name sgi vrf 200",
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			"upf gtpu endpoint ip 10.0.0.2 nwi cp teid 0x80000000/2",
			"upf gtpu endpoint ip 10.0.3.2 nwi epc teid 0x80000000/2",
			// NOTE: both IP and subnet (ip4 or ipv6) should be variable below
			// For IPv6, ::/0 should be used as the subnet
			"ip route add 0.0.0.0/0 table 200 via 10.0.2.3 host-sgi0",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver-.*",
			// TODO: make stitching optional and verify it
			"set upf proxy mss 1250",
		},
	}
}
