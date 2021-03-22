// utils.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"log"
	"net"
	"regexp"
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

var invalidFilenameCharsRx = regexp.MustCompile(`[^-\w.]`)

func toFilename(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "_")
	return invalidFilenameCharsRx.ReplaceAllString(s, "")
}
