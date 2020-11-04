package framework

import (
	"log"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

func MustParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		log.Panicf("failed to parse IP %q", s)
	}
	return ip
}

func MustParseIPNet(s string) *net.IPNet {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		log.Panicf("failed to parse CIDR %q: %v", s, err)
	}
	ipNet.IP = ip
	return ipNet
}

func MustParseMAC(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil {
		log.Panicf("failed to parse MAC address %q: %v", s, err)
	}
	return hw
}

func EncodeAPN(s string) string {
	var r []rune
	for _, p := range strings.Split(s, ".") {
		r = append(r, rune(len(p)))
		r = append(r, []rune(p)...)
	}
	return string(r)
}

func RunningInLinuxkit() bool {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return false
	}

	return strings.Contains(string(uname.Release[:]), "linuxkit")
}
