// uplane_shared.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package sgw

import (
	"net"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

const route_table_id = 1122

type tunnelShared struct {
	up  *UserPlaneServer
	cfg SGWGTPUTunnel
}

func newTunnelShared(up *UserPlaneServer, cfg SGWGTPUTunnel) tunnelShared {
	return tunnelShared{
		up:  up,
		cfg: cfg,
	}
}

func (ts *tunnelShared) cleanup() error {
	if err := ts.removeIface(*ts.up.grxHandle); err != nil {
		return errors.Wrap(err, "Failed to remove gtpu tunnel")
	}

	if err := ts.removeIface(*ts.up.ueHandle); err != nil {
		return errors.Wrap(err, "Failed to remove gtpu tunnel")
	}

	return nil
}

func (ts *tunnelShared) removeIface(handle netlink.Handle) error {
	if existingLink, err := handle.LinkByName(ts.cfg.InterfaceName); err == nil {
		if err := handle.LinkDel(existingLink); err != nil {
			return errors.Wrap(err, "Failed to remove interface")
		}
	}
	return nil
}

func (ts *tunnelShared) prepareIPNet(ip net.IP) *net.IPNet {
	var mask net.IPMask
	if ip.To4() == nil {
		mask = net.CIDRMask(64, 128)
	} else {
		mask = net.CIDRMask(32, 32)
	}
	return &net.IPNet{IP: ip, Mask: mask}
}

func (ts *tunnelShared) prepareRoute(ip net.IP, link netlink.Link) *netlink.Route {
	var mask net.IPMask
	var zeroip net.IP
	var proto int

	if ip.To4() == nil {
		mask = net.CIDRMask(0, 128)
		zeroip = net.IPv6zero
		proto = 6
	} else {
		mask = net.CIDRMask(0, 32)
		zeroip = net.IPv4zero
		proto = 4
	}

	tableId := 0
	if ts.up.cfg.AddRule {
		tableId = route_table_id
	}

	return &netlink.Route{
		Dst:       &net.IPNet{IP: zeroip, Mask: mask},
		LinkIndex: link.Attrs().Index,
		Scope:     SCOPE_LINK,
		Protocol:  proto,
		Priority:  1,
		Table:     tableId,
	}
}

func (ts *tunnelShared) prepareIP(ip net.IP) *netlink.Addr {
	return &netlink.Addr{
		IPNet: ts.prepareIPNet(ip),
		Label: ts.cfg.InterfaceName,
	}
}

func (ts *tunnelShared) addRoute(ip net.IP, link netlink.Link) error {
	if err := ts.up.ueHandle.RouteReplace(ts.prepareRoute(ip, link)); err != nil {
		return errors.Wrapf(err, "Route replace fail")
	}
	return nil
}

func (ts *tunnelShared) addIP(ip net.IP, link netlink.Link) error {
	addrs, err := ts.up.ueHandle.AddrList(link, FAMILY_ALL)
	if err != nil {
		return errors.Wrapf(err, "Failed to get address list")
	}

	for _, a := range addrs {
		if a.IPNet.IP.Equal(ip) {
			// already added
			return errors.Errorf("Address %q already added to interface %s", a.IP.String(), ts.cfg.InterfaceName)
		}
	}

	if err := ts.up.ueHandle.AddrAdd(link, ts.prepareIP(ip)); err != nil {
		return errors.Wrapf(err, "Failed to AddrAdd")
	}

	return nil
}

func (ts *tunnelShared) prepareRule(ip net.IP) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Src = ts.prepareIPNet(ip)
	rule.Table = route_table_id
	return rule
}

func (ts *tunnelShared) addRuleLocal(ip net.IP) error {
	rules, err := ts.up.ueHandle.RuleList(0)
	if err != nil {
		return errors.Wrapf(err, "Failed to get netlink rule list")
	}

	newRule := ts.prepareRule(ip)

	for _, r := range rules {
		if r.Src == newRule.Src && r.Table == newRule.Table {
			return nil
		}
	}

	if err := ts.up.ueHandle.RuleAdd(newRule); err != nil {
		return errors.Wrapf(err, "Failed to add netlink rule")
	}

	return nil
}

func (ts *tunnelShared) addRouteAndIPAndRule(ip net.IP, link netlink.Link) error {
	if err := ts.addIP(ip, link); err != nil {
		return errors.Wrap(err, "Failed to add ip")
	}

	if err := ts.addRoute(ip, link); err != nil {
		return errors.Wrap(err, "Failed to add route")
	}

	if ts.up.cfg.AddRule {
		if err := ts.addRuleLocal(ip); err != nil {
			return errors.Wrap(err, "Failed to add rule")
		}
	}

	return nil
}

func (ts *tunnelShared) removeRouteAndIPAndRule(ip net.IP, link netlink.Link) error {
	errs := make([]string, 0, 3)

	if ts.up.cfg.AddRule {
		if err := ts.up.ueHandle.RuleDel(ts.prepareRule(ip)); err != nil {
			errs = append(errs, errors.Wrap(err, "Failed to remove rule").Error())
		}
	}

	if err := ts.up.ueHandle.AddrDel(link, ts.prepareIP(ip)); err != nil {
		errs = append(errs, errors.Wrap(err, "Failed to remove address").Error())
	}

	if len(errs) == 0 {
		return nil
	} else {
		return errors.Errorf("%v", errs)
	}
}
