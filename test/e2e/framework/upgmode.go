// upgmode.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package framework

import (
	"github.com/travelping/upg-vpp/test/e2e/vpp"
)

type UPGMode int

const (
	UPGModeNone UPGMode = iota
	UPGModePGW
	UPGModeTDF
	UPGModeGTPProxy
)

type UPGIPMode int

const (
	UPGIPModeNone UPGIPMode = iota
	UPGIPModeV4
	UPGIPModeV6
)

type upgModeKey struct {
	UPGMode
	UPGIPMode
}

type upgModeFunc func() vpp.VPPConfig

var upgModeTable = map[upgModeKey]upgModeFunc{
	{UPGModePGW, UPGIPModeV4}:      pgwVPPConfigIPv4,
	{UPGModePGW, UPGIPModeV6}:      pgwVPPConfigIPv6,
	{UPGModeTDF, UPGIPModeV4}:      tdfVPPConfigIPv4,
	{UPGModeTDF, UPGIPModeV6}:      tdfVPPConfigIPv6,
	{UPGModeGTPProxy, UPGIPModeV4}: gtpProxyVPPConfigIPv4,
	{UPGModeGTPProxy, UPGIPModeV6}: gtpProxyVPPConfigIPv6,
}

func vppConfig(mode UPGMode, ipMode UPGIPMode) vpp.VPPConfig {
	k := upgModeKey{mode, ipMode}
	modeFunc, found := upgModeTable[k]
	if !found {
		panic("bad UPGMode / UPGIPMode")
	}
	return modeFunc()
}

func pgwVPPConfigIPv4() vpp.VPPConfig {
	return vpp.VPPConfig{
		Namespaces: []vpp.VPPNetworkNamespace{
			{
				Name:          "cp",
				VPPMac:        MustParseMAC("fa:8a:78:4d:5b:5b"),
				VPPIP:         MustParseIPNet("10.0.0.2/24"),
				OtherIP:       MustParseIPNet("10.0.0.3/24"),
				VPPLinkName:   "cp0",
				OtherLinkName: "cp1",
				Table:         0,
				Placement:     -1, // main thread
			},
			{
				Name:          "ue",
				OtherIP:       MustParseIPNet("10.1.0.3/16"),
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
				VPPIP:         MustParseIPNet("10.0.2.2/24"),
				OtherIP:       MustParseIPNet("10.0.2.3/24"),
				VPPLinkName:   "grx0",
				OtherLinkName: "grx1",
				Table:         100,
			},
			{
				Name:          "sgi",
				VPPMac:        MustParseMAC("fa:8a:78:4d:19:01"),
				VPPIP:         MustParseIPNet("10.0.1.2/24"),
				OtherIP:       MustParseIPNet("10.0.1.3/24"),
				VPPLinkName:   "sgi0",
				OtherLinkName: "sgi1",
				Table:         200,
				NSRoutes: []vpp.RouteConfig{
					{
						Dst: MustParseIPNet("10.1.0.0/16"),
						Gw:  MustParseIP("10.0.1.2"),
					},
				},
			},
		},
		NWIs: []vpp.NWIConfig{
			{Name: "cp", Table: 0},
			{Name: "epc", Table: 100},
			{Name: "sgi", Table: 200},
		},
		SetupCommands: []string{
			"upf node-id fqdn upg",
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			"upf gtpu endpoint ip 10.0.0.2 nwi cp teid 0x80000000/2",
			"upf gtpu endpoint ip 10.0.2.2 nwi epc teid 0x80000000/2",
			// NOTE: both IP and subnet (ip4 or ipv6) should be variable below
			// For IPv6, ::/0 should be used as the subnet
			"ip route add 0.0.0.0/0 table 200 via 10.0.2.3 host-sgi0",
			"create upf application name IPAPP",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver[46]-.*",
			// TODO: make stitching optional and verify it
			// TODO: optional trace
			"?set upf proxy mss 1250",
		},
	}
}

func pgwVPPConfigIPv6() vpp.VPPConfig {
	return vpp.VPPConfig{
		Namespaces: []vpp.VPPNetworkNamespace{
			{
				Name:          "cp",
				VPPMac:        MustParseMAC("fa:8a:78:4d:5b:5b"),
				VPPIP:         MustParseIPNet("10.0.0.2/24"),
				OtherIP:       MustParseIPNet("10.0.0.3/24"),
				VPPLinkName:   "cp0",
				OtherLinkName: "cp1",
				Table:         0,
				Placement:     -1, // main thread
			},
			{
				Name:          "ue",
				OtherIP:       MustParseIPNet("2001:db8:11::3/64"),
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
				VPPIP:         MustParseIPNet("2001:db8:13::2/64"),
				OtherIP:       MustParseIPNet("2001:db8:13::3/64"),
				VPPLinkName:   "grx0",
				OtherLinkName: "grx1",
				Table:         100,
			},
			{
				Name:          "sgi",
				VPPMac:        MustParseMAC("fa:8a:78:4d:19:01"),
				VPPIP:         MustParseIPNet("2001:db8:12::2/64"),
				OtherIP:       MustParseIPNet("2001:db8:12::3/64"),
				VPPLinkName:   "sgi0",
				OtherLinkName: "sgi1",
				Table:         200,
				NSRoutes: []vpp.RouteConfig{
					{
						Dst: MustParseIPNet("2001:db8:11::/64"),
						Gw:  MustParseIP("2001:db8:12::2"),
					},
				},
			},
		},
		NWIs: []vpp.NWIConfig{
			{Name: "cp", Table: 0},
			{Name: "epc", Table: 100},
			{Name: "sgi", Table: 200},
		},
		SetupCommands: []string{
			"upf node-id fqdn upg",
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			"upf gtpu endpoint ip 10.0.0.2 nwi cp teid 0x80000000/2",
			// FIXME: zero udp checksum on Session Modification Responses
			// "upf pfcp endpoint ip 2001:db8:10::2 vrf 0",
			// "upf gtpu endpoint ip6 2001:db8:10::2 nwi cp teid 0x80000000/2",
			"upf gtpu endpoint ip6 2001:db8:13::2 nwi epc teid 0x80000000/2",
			"ip route add ::/0 table 200 via 2001:db8:12::3 host-sgi0",
			"create upf application name IPAPP",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver[46]-.*",
			// TODO: make stitching optional and verify it
			"?set upf proxy mss 1250",
		},
	}
}

func tdfVPPConfigIPv4() vpp.VPPConfig {
	return vpp.VPPConfig{
		Namespaces: []vpp.VPPNetworkNamespace{
			{
				Name:          "cp",
				VPPMac:        MustParseMAC("fa:8a:78:4d:5b:5b"),
				VPPIP:         MustParseIPNet("10.0.0.2/24"),
				OtherIP:       MustParseIPNet("10.0.0.3/24"),
				VPPLinkName:   "cp0",
				OtherLinkName: "cp1",
				Table:         0,
				Placement:     -1, // main thread
			},
			{
				Name:          "ue",
				VPPMac:        MustParseMAC("fa:8a:78:4d:18:01"),
				VPPIP:         MustParseIPNet("10.1.0.2/16"),
				OtherIP:       MustParseIPNet("10.1.0.3/16"),
				VPPLinkName:   "access0",
				OtherLinkName: "access1",
				Table:         100,
				NSRoutes: []vpp.RouteConfig{
					{
						Gw: MustParseIP("10.1.0.2"),
					},
				},
			},
			{
				Name:          "sgi",
				VPPMac:        MustParseMAC("fa:8a:78:4d:19:01"),
				VPPIP:         MustParseIPNet("10.0.1.2/24"),
				OtherIP:       MustParseIPNet("10.0.1.3/24"),
				VPPLinkName:   "sgi0",
				OtherLinkName: "sgi1",
				Table:         200,
				NSRoutes: []vpp.RouteConfig{
					{
						Dst: MustParseIPNet("10.1.0.0/16"),
						Gw:  MustParseIP("10.0.1.2"),
					},
					{
						// Used for NAT verification
						Dst: MustParseIPNet("144.0.0.0/24"),
						Gw:  MustParseIP("10.0.1.2"),
					},
				},
			},
		},
		NWIs: []vpp.NWIConfig{
			{Name: "cp", Table: 0},
			{Name: "access", Table: 100},
			{Name: "sgi", Table: 200},
		},
		SetupCommands: []string{
			"upf node-id ip4 172.1.1.1",
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			// NOTE: "ip6" instead of "ip4" for IPv6
			"upf tdf ul table vrf 100 ip4 table-id 1001",
			// NOTE: "ip6" instead of "ip4" for IPv6
			"upf tdf ul enable ip4 host-access0",
			// NOTE: both IP and subnet (ip4 or ipv6) should be variable below
			// For IPv6, ::/0 should be used as the subnet
			"ip route add 0.0.0.0/0 table 200 via 10.0.2.3 host-sgi0",
			"create upf application name IPAPP",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver[46]-.*",
			// TODO: make stitching optional and verify it
			"?set upf proxy mss 1250",
		},
	}
}

func tdfVPPConfigIPv6() vpp.VPPConfig {
	return vpp.VPPConfig{
		Namespaces: []vpp.VPPNetworkNamespace{
			{
				Name:          "cp",
				VPPMac:        MustParseMAC("fa:8a:78:4d:5b:5b"),
				VPPIP:         MustParseIPNet("10.0.0.2/24"),
				OtherIP:       MustParseIPNet("10.0.0.3/24"),
				VPPLinkName:   "cp0",
				OtherLinkName: "cp1",
				Table:         0,
				Placement:     -1, // main thread
			},
			{
				Name:          "ue",
				VPPMac:        MustParseMAC("fa:8a:78:4d:18:01"),
				VPPIP:         MustParseIPNet("2001:db8:11::2/64"),
				OtherIP:       MustParseIPNet("2001:db8:11::3/64"),
				VPPLinkName:   "access0",
				OtherLinkName: "access1",
				Table:         100,
				NSRoutes: []vpp.RouteConfig{
					{
						Gw: MustParseIP("2001:db8:11::2"),
					},
				},
			},
			{
				Name:          "sgi",
				VPPMac:        MustParseMAC("fa:8a:78:4d:19:01"),
				VPPIP:         MustParseIPNet("2001:db8:12::2/64"),
				OtherIP:       MustParseIPNet("2001:db8:12::3/64"),
				VPPLinkName:   "sgi0",
				OtherLinkName: "sgi1",
				Table:         200,
				NSRoutes: []vpp.RouteConfig{
					{
						Dst: MustParseIPNet("2001:db8:11::/64"),
						Gw:  MustParseIP("2001:db8:12::2"),
					},
				},
			},
		},
		NWIs: []vpp.NWIConfig{
			{Name: "cp", Table: 0},
			{Name: "access", Table: 100},
			{Name: "sgi", Table: 200},
		},
		SetupCommands: []string{
			"upf node-id ip4 172.1.1.1",
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			// FIXME: zero udp checksum on Session Modification Responses
			// "upf pfcp endpoint ip 2001:db8:10::2 vrf 0",
			"upf tdf ul table vrf 100 ip6 table-id 1001",
			"upf tdf ul enable ip6 host-access0",
			"ip route add ::/0 table 200 via 2001:db8:12::3 host-sgi0",
			"create upf application name IPAPP",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver[46]-.*",
			// TODO: make stitching optional and verify it
			"?set upf proxy mss 1250",
		},
	}
}

func gtpProxyVPPConfigIPv4() vpp.VPPConfig {
	return vpp.VPPConfig{
		Namespaces: []vpp.VPPNetworkNamespace{
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
				OtherIP:       MustParseIPNet("10.1.0.3/16"),
				OtherLinkName: "access",
				SkipVPPConfig: true,
				// using L3 capture because of tun
				// (no Ethernet headers)
				L3Capture: true,
				// the default route is added by gtpu (sgw) code here
			},
			{
				Name:          "access",
				VPPMac:        MustParseMAC("fa:8a:78:4d:42:01"),
				VPPIP:         MustParseIPNet("10.0.2.2/24"),
				OtherIP:       MustParseIPNet("10.0.2.3/24"),
				VPPLinkName:   "access0",
				OtherLinkName: "access1",
				Table:         100,
			},
			{
				Name:          "core",
				VPPMac:        MustParseMAC("fa:8a:78:4d:99:01"),
				VPPIP:         MustParseIPNet("10.0.3.2/24"),
				OtherIP:       MustParseIPNet("10.0.3.3/24"),
				VPPLinkName:   "core0",
				OtherLinkName: "core1",
				Table:         200,
			},
			{
				Name:          "srv",
				OtherIP:       MustParseIPNet("10.0.1.3/24"),
				OtherLinkName: "srv1",
				SkipVPPConfig: true,
				// using L3 capture because of tun
				// (no Ethernet headers)
				L3Capture: true,
				// the default route is added by gtpu (sgw) code here
			},
		},
		NWIs: []vpp.NWIConfig{
			{Name: "cp", Table: 0},
			{Name: "access", Table: 100},
			{Name: "core", Table: 200},
		},
		SetupCommands: []string{
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			"upf gtpu endpoint ip 10.0.0.2 nwi cp teid 0x80000000/2",
			"upf gtpu endpoint ip 10.0.2.2 nwi access teid 0x80000000/2",
			"upf gtpu endpoint ip 10.0.3.2 nwi core teid 0x80000000/2",
			"create upf application name IPAPP",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver[46]-.*",
			// TODO: make stitching optional and verify it
			// TODO: optional trace
			"?set upf proxy mss 1250",
		},
	}
}

func gtpProxyVPPConfigIPv6() vpp.VPPConfig {
	return vpp.VPPConfig{
		Namespaces: []vpp.VPPNetworkNamespace{
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
				OtherIP:       MustParseIPNet("2001:db8:11::3/64"),
				OtherLinkName: "access",
				SkipVPPConfig: true,
				// using L3 capture because of tun
				// (no Ethernet headers)
				L3Capture: true,
				// the default route is added by gtpu (sgw) code here
			},
			{
				Name:          "access",
				VPPMac:        MustParseMAC("fa:8a:78:4d:42:01"),
				VPPIP:         MustParseIPNet("2001:db8:13::2/64"),
				OtherIP:       MustParseIPNet("2001:db8:13::3/64"),
				VPPLinkName:   "access0",
				OtherLinkName: "access1",
				Table:         100,
			},
			{
				Name:          "core",
				VPPMac:        MustParseMAC("fa:8a:78:4d:99:01"),
				VPPIP:         MustParseIPNet("2001:db8:14::2/64"),
				OtherIP:       MustParseIPNet("2001:db8:14::3/64"),
				VPPLinkName:   "core0",
				OtherLinkName: "core1",
				Table:         200,
			},
			{
				Name:          "srv",
				OtherIP:       MustParseIPNet("2001:db8:12::3/64"),
				OtherLinkName: "srv1",
				SkipVPPConfig: true,
				// using L3 capture because of tun
				// (no Ethernet headers)
				L3Capture: true,
				// the default route is added by gtpu (sgw) code here
			},
		},
		NWIs: []vpp.NWIConfig{
			{Name: "cp", Table: 0},
			{Name: "access", Table: 100},
			{Name: "core", Table: 200},
		},
		SetupCommands: []string{
			"upf pfcp endpoint ip 10.0.0.2 vrf 0",
			"upf gtpu endpoint ip 10.0.0.2 nwi cp teid 0x80000000/2",
			"upf gtpu endpoint ip6 2001:db8:13::2 nwi access teid 0x80000000/2",
			"upf gtpu endpoint ip6 2001:db8:14::2 nwi core teid 0x80000000/2",
			"create upf application name IPAPP",
			"create upf application proxy name TST",
			"upf application TST rule 3000 add l7 regex ^https?://theserver[46]-.*",
			// TODO: make stitching optional and verify it
			// TODO: optional trace
			"?set upf proxy mss 1250",
		},
	}
}
