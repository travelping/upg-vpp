// +build linux

package framework

import (
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/vishvananda/netlink"
)

const (
	FAMILY_ALL = netlink.FAMILY_ALL
	FAMILY_V4  = netlink.FAMILY_V4
	FAMILY_V6  = netlink.FAMILY_V6
)

func Sysctl(name string, params ...string) (string, error) {
	return sysctl.Sysctl(name, params...)
}
