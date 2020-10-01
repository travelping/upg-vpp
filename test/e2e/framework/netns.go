package framework

// import (
// 	"github.com/containernetworking/plugins/pkg/ns"
// 	"github.com/containernetworking/plugins/pkg/testutils"
// 	"github.com/pkg/errors"
// 	"github.com/vishvananda/netlink"
// )

// type NetNS struct {
// 	ns.NetNS
// }

// func (netns *NetNS) Close() error {
// 	if err := netns.Close(); err != nil {
// 		return err
// 	}

// 	return testutils.UnmountNS(netns)
// }

// func (netns *NetNS) AddAddress(linkName, address string) error {
// 	return netns.Do(func(_ ns.NetNS) error {
// 		veth, err := netlink.LinkByName(linkName)
// 		if err != nil {
// 			return errors.Wrap(err, "locating client link in the client netns")
// 		}

// 		if err := netlink.AddrAdd(veth, mustParseAddr(address)); err != nil {
// 			return errors.Errorf("failed to set address for the bridge: %v", err)
// 		}

// 		return nil
// 	})
// }
