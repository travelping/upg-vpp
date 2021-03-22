// utils_linux.go - 3GPP TS 29.244 GTP-U UP plug-in
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

// +build linux

package network

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
