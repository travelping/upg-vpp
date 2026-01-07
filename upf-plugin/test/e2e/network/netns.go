// netns.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package network

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/travelping/upg-vpp/test/e2e/ns"
	"github.com/vishvananda/netlink"
	nns "github.com/vishvananda/netns"
)

var (
	ethFeatureRx = regexp.MustCompile("^[rt]x-(checksum.*|.*segmentation|.*fragmentation|scatter-gather.*|gro)$")
)

type NetemAttrs netlink.NetemQdiscAttrs

type NetNS struct {
	ns.NetNS
	Name     string
	cleanups []func()
	ipv6     bool
}

func NewNS(name string) (*NetNS, error) {
	innerNS, err := ns.NewNS(name)
	if err != nil {
		return nil, err
	}

	return &NetNS{
		NetNS: innerNS,
		Name:  name,
	}, nil
}

func (netns *NetNS) Handle() nns.NsHandle {
	return nns.NsHandle(netns.Fd())
}

func (netns *NetNS) Do(toCall func() error) error {
	return netns.NetNS.Do(func(_ ns.NetNS) error {
		return toCall()
	})
}

func (netns *NetNS) Close() error {
	for _, cleanupFunc := range netns.cleanups {
		cleanupFunc()
	}
	return netns.NetNS.Close()
}

func (netns *NetNS) SetLinkUp(linkName string) error {
	return netns.Do(func() error {
		l, err := netlink.LinkByName(linkName)
		if err != nil {
			return errors.Wrap(err, "locating client link in the client netns")
		}

		if err := netlink.LinkSetUp(l); err != nil {
			return errors.Wrapf(err, "error bringing the link up: %s", linkName)
		}

		return nil
	})
}

func (netns *NetNS) AddAddress(linkName string, address *net.IPNet) error {
	// FIXME: use better check
	if address.IP.To4() == nil {
		netns.ipv6 = true
	}
	return netns.Do(func() error {
		// Golang netlink library was adding some defaults (like broadcast) and failed for /32 adresses.
		// Simpler to use iproute2 in this case
		_, err := exec.Command("ip", "a", "add", "dev", linkName, address.String(), "noprefixroute").CombinedOutput()
		return err
	})
}

func (netns *NetNS) control(network, address string, c syscall.RawConn) error {
	log := logrus.WithFields(logrus.Fields{
		"netns":   netns.Name,
		"network": network,
		"address": address,
	})
	log.Trace("dial invoked")
	curns, err := ns.GetCurrentNS()
	if err != nil {
		return errors.Wrap(err, "error getting current netns")
	}

	eq, err := netns.Equal(curns)
	if err != nil {
		return errors.Wrap(err, "error comparing the network namespaces")
	}

	if eq {
		return nil
	}

	// Too bad! We've hit another goroutine,
	// need to switch netns, and we will have to keep
	// this goroutine under LockOSThread(), so it will
	// be disposed of by the runtime afterwards.
	// That's because Control is not a wrapper
	// around the system call, but is rather called
	// before invoking it
	log.Debug("correcting netns")
	runtime.LockOSThread()
	if err := netns.Set(); err != nil {
		return errors.Wrap(err, "error setting network namespace")
	}

	return nil
}

// dialer retuns a net.Dialer that ensures that the actual system call
// is performed from within the correct namespace
func (netns *NetNS) dialer(laddr net.Addr) *net.Dialer {
	return &net.Dialer{
		LocalAddr: laddr,
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   netns.control,
	}
}

// listenConfig retuns a net.ListenConfig that ensures that the actual system call
// is performed from within the correct namespace
func (netns *NetNS) listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: netns.control,
	}
}

func (netns *NetNS) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// TODO: Right now, it's important to pass a single IPv4 /
	// IPv6 address here, otherwise DialContext will try multiple
	// connections in parallel, spawning goroutines which can get
	// other network namespace.
	//
	// As it can easily be seen, this approach is rather fragile,
	// and chances are we could improve the situation by using
	// Control hook in the net.Dialer. The Control function could
	// check if the correct network namespace is being used, and
	// if it isn't the case, call runtime.LockOSThread() and
	// switch to the right one.
	var conn net.Conn
	err := netns.Do(func() error {
		var innerErr error
		conn, innerErr = netns.dialer(nil).DialContext(ctx, network, address)
		return innerErr
	})
	return conn, err
}

func (netns *NetNS) dialParams(proto string, laddr net.Addr, raddr net.IP) (string, net.Addr) {
	network := proto + "4"
	if netns.ipv6 || raddr.To4() == nil {
		network = proto + "6"
	}
	var la net.Addr
	if laddr != nil {
		// pass proper nil (not interface value)
		la = laddr
	}
	return network, la
}

func (netns *NetNS) DialUDP(ctx context.Context, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	var conn net.Conn
	err := netns.Do(func() error {
		var innerErr error
		network, la := netns.dialParams("udp", laddr, raddr.IP)
		conn, innerErr = netns.dialer(la).DialContext(ctx, network, raddr.String())
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), err
}

func (netns *NetNS) DialTCP(ctx context.Context, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	var conn net.Conn
	err := netns.Do(func() error {
		var innerErr error
		network, la := netns.dialParams("tcp", laddr, raddr.IP)
		conn, innerErr = netns.dialer(la).DialContext(ctx, network, raddr.String())
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), err
}

func (netns *NetNS) DialTCPTimeout(ctx context.Context, laddr, raddr *net.TCPAddr, timeout time.Duration) (*net.TCPConn, error) {
	var conn net.Conn
	err := netns.Do(func() error {
		var innerErr error
		network, la := netns.dialParams("tcp", laddr, raddr.IP)
		dialer := netns.dialer(la)
		dialer.Timeout = timeout
		conn, innerErr = dialer.DialContext(ctx, network, raddr.String())
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), err
}

func (netns *NetNS) ListenTCP(ctx context.Context, address string) (net.Listener, error) {
	var l net.Listener
	err := netns.Do(func() error {
		var innerErr error
		network := "tcp4"
		if netns.ipv6 || strings.HasPrefix(address, "[") {
			network = "tcp6"
		}
		l, innerErr = netns.listenConfig().Listen(context.Background(), network, address)
		return innerErr
	})
	return l, err
}

func (netns *NetNS) ListenUDP(ctx context.Context, laddr *net.UDPAddr) (*net.UDPConn, error) {
	var c net.PacketConn
	err := netns.Do(func() error {
		var innerErr error
		network := "udp4"
		if netns.ipv6 || laddr.IP.To4() == nil {
			network = "udp6"
		}
		c, innerErr = netns.listenConfig().ListenPacket(ctx, network, laddr.String())
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), err
}

func (netns *NetNS) AddCleanup(toCall func()) {
	netns.cleanups = append(netns.cleanups, toCall)
}

func (netns *NetNS) AddRoute(dst *net.IPNet, gw net.IP) error {
	return netns.Do(func() error {
		if dst == nil {
			if gw.To4() == nil {
				dst = &net.IPNet{
					IP:   make([]byte, 16),
					Mask: make([]byte, 16),
				}
			} else {
				dst = &net.IPNet{
					IP:   make([]byte, 4),
					Mask: make([]byte, 4),
				}
			}
		}

		if err := netlink.RouteAdd(&netlink.Route{
			Dst: dst,
			Gw:  gw,
		}); err != nil {
			dstStr := "default"
			if dst != nil {
				dstStr = dst.String()
			}
			return errors.Wrapf(err, "add route %s via %s", dstStr, gw)
		}

		return nil
	})
}

func (netns *NetNS) AddRouteLink(link string, dst *net.IPNet, src net.IP) error {
	return netns.Do(func() error {
		l, err := netlink.LinkByName(link)
		if err != nil {
			return errors.Errorf("get interface %s", link)
		}

		newRoute := &netlink.Route{
			Dst:       dst,
			Scope:     netlink.SCOPE_LINK,
			Src:       src,
			LinkIndex: l.Attrs().Index,
		}

		return errors.Wrapf(netlink.RouteAdd(newRoute), "add scope route %v src %v", dst, src)
	})
}

func (netns *NetNS) SetIPv6() {
	netns.ipv6 = true
}
