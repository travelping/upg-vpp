package framework

import (
	"context"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/travelping/upg-vpp/test/e2e/ns"
)

const (
	MTU        = 9000
	NO_ADDRESS = ""
)

type NetNS struct {
	ns.NetNS
	IPNet *net.IPNet
}

func NewNS() (*NetNS, error) {
	innerNS, err := ns.NewNS()
	if err != nil {
		return nil, err
	}
	return &NetNS{
		NetNS: innerNS,
	}, nil
}

func (netns *NetNS) AddAddress(linkName, address string) error {
	return netns.Do(func(_ ns.NetNS) error {
		veth, err := netlink.LinkByName(linkName)
		if err != nil {
			return errors.Wrap(err, "locating client link in the client netns")
		}

		addr, err := netlink.ParseAddr(address)
		if err != nil {
			return errors.Wrapf(err, "failed to parse address %q", address)
		}

		if err := netlink.AddrAdd(veth, addr); err != nil {
			return errors.Errorf("failed to set address for the bridge: %v", err)
		}

		netns.IPNet = addr.IPNet

		return nil
	})
}

func (netns *NetNS) SetupVethPair(thisLinkName, thisAddress string, other *NetNS, otherLinkName, otherAddress string) error {
	if err := netns.Do(func(_ ns.NetNS) error {
		if _, _, err := SetupVethWithName(thisLinkName, otherLinkName, MTU, other); err != nil {
			return errors.Wrap(err, "creating veth pair")
		}
		return nil
	}); err != nil {
		return err
	}

	if thisAddress != NO_ADDRESS {
		if err := netns.AddAddress(thisLinkName, thisAddress); err != nil {
			return errors.Wrapf(err, "error adding address to link %s", thisLinkName)
		}
	}

	if otherAddress != NO_ADDRESS {
		if err := other.AddAddress(otherLinkName, otherAddress); err != nil {
			return errors.Wrapf(err, "error adding address to link %s", otherLinkName)
		}
	}

	return nil
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
	err := netns.Do(func(_ ns.NetNS) error {
		var innerErr error
		conn, innerErr = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, address)
		return innerErr
	})
	return conn, err
}

func (netns *NetNS) ListenTCP(address string) (net.Listener, error) {
	var l net.Listener
	err := netns.Do(func(_ ns.NetNS) error {
		var innerErr error
		l, innerErr = net.Listen("tcp", address)
		return innerErr
	})
	return l, err
}
