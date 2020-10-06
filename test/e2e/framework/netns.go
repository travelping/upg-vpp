package framework

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/pkg/errors"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"github.com/travelping/upg-vpp/test/e2e/ns"
)

const (
	MTU = 9000
)

var (
	ethFeatureRx = regexp.MustCompile("^[rt]x-(checksum.*|.*segmentation|.*fragmentation|scatter-gather.*|gro)$")
)

type NetNS struct {
	ns.NetNS
	IPNet    *net.IPNet
	tcpDumps map[string]*exec.Cmd
}

func NewNS(name string) (*NetNS, error) {
	innerNS, err := ns.NewNS(name)
	if err != nil {
		return nil, err
	}
	return &NetNS{
		NetNS:    innerNS,
		tcpDumps: make(map[string]*exec.Cmd),
	}, nil
}

func (netns *NetNS) Close() error {
	for iface, cmd := range netns.tcpDumps {
		fmt.Printf("* stopping capture for %s\n", iface)
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	}
	return netns.NetNS.Close()
}

func (netns *NetNS) disableOffloading(linkName string) error {
	return netns.Do(func(_ ns.NetNS) error {
		et, err := ethtool.NewEthtool()
		if err != nil {
			return errors.Wrap(err, "NewEthtool")
		}
		features, err := et.Features(linkName)
		if err != nil {
			return errors.Wrap(err, "Features")
		}
		updateFeatures := make(map[string]bool)
		for name, value := range features {
			if ethFeatureRx.MatchString(name) && value {
				fmt.Printf("ethtool %s: %s off\n", linkName, name)
				updateFeatures[name] = false
			}
		}
		if len(updateFeatures) > 0 {
			if err := et.Change(linkName, updateFeatures); err != nil {
				return errors.Wrapf(err, "change eth features: %#v", updateFeatures)
			}
		}
		return nil
	})
}

func (netns *NetNS) AddAddress(linkName string, address *net.IPNet) error {
	return netns.Do(func(_ ns.NetNS) error {
		veth, err := netlink.LinkByName(linkName)
		if err != nil {
			return errors.Wrap(err, "locating client link in the client netns")
		}

		if err := netlink.AddrAdd(veth, &netlink.Addr{IPNet: address}); err != nil {
			return errors.Errorf("failed to set address for the bridge: %v", err)
		}

		netns.IPNet = address
		return nil
	})
}

func (netns *NetNS) SetupVethPair(thisLinkName string, thisAddress *net.IPNet, other *NetNS, otherLinkName string, otherAddress *net.IPNet) error {
	if err := netns.Do(func(_ ns.NetNS) error {
		if _, _, err := SetupVethWithName(thisLinkName, otherLinkName, MTU, other); err != nil {
			return errors.Wrap(err, "creating veth pair")
		}
		return nil
	}); err != nil {
		return err
	}

	if err := netns.disableOffloading(thisLinkName); err != nil {
		return errors.Wrapf(err, "disable offloading for %s", thisLinkName)
	}

	if err := other.disableOffloading(otherLinkName); err != nil {
		return errors.Wrapf(err, "disable offloading for %s", otherLinkName)
	}

	if thisAddress != nil {
		if err := netns.AddAddress(thisLinkName, thisAddress); err != nil {
			return errors.Wrapf(err, "error adding address to link %s", thisLinkName)
		}
	}

	if otherAddress != nil {
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

func (netns *NetNS) DialUDP(laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	var conn *net.UDPConn
	err := netns.Do(func(_ ns.NetNS) error {
		var innerErr error
		conn, innerErr = net.DialUDP("udp", laddr, raddr)
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

func (netns *NetNS) StartCapture(iface, pcapPath string) error {
	// TODO: use gopacket
	// https://github.com/google/gopacket/blob/master/examples/pfdump/main.go
	if _, found := netns.tcpDumps[iface]; found {
		return errors.Errorf("tcpdump already started for interface %s", iface)
	}
	cmd := exec.Command(
		"nsenter", "--net="+netns.Path(),
		"tcpdump", "-n", "-i", iface, "-w", pcapPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return errors.Wrap(err, "error starting tcpdump")
	}
	// FIXME (let tcpdump start capturing)
	<-time.After(1 * time.Second)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return errors.New("tcpdump has exited")
	}
	netns.tcpDumps[iface] = cmd
	return nil
}

func (netns *NetNS) AddRoute(dst *net.IPNet, gw net.IP) error {
	return netns.Do(func(_ ns.NetNS) error {
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

// https://github.com/safchain/ethtool/blob/8f958a28363a963779d180bc3d3715ab1333e1de/ethtool.go#L513
