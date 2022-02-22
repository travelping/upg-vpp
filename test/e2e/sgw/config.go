// config.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"context"
	"net"

	"github.com/vishvananda/netns"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

type SGWGTPUTunnelType string

const (
	SGWGTPUTunnelTypeNone   SGWGTPUTunnelType = ""
	SGWGTPUTunnelTypeKernel SGWGTPUTunnelType = "kernel"
	SGWGTPUTunnelTypeTun    SGWGTPUTunnelType = "tun"
)

type NetNS interface {
	Handle() netns.NsHandle
	ListenUDP(ctx context.Context, laddr *net.UDPAddr) (*net.UDPConn, error)
	Do(toCall func() error) error
}

type SGWGTPUTunnel struct {
	Type          SGWGTPUTunnelType `yaml:"type"`
	InterfaceName string            `yaml:"interface_name" default:"gtpu_sgw"`
	MTU           int               `yaml:"mtu" default:"1300"`
}

type TPDUHook func(tpdu *message.TPDU, fromPGW bool)

type UserPlaneConfig struct {
	S5uIP      net.IP
	GTPUTunnel SGWGTPUTunnel
	GRXNetNS   NetNS
	UENetNS    NetNS
	AddRule    bool
	// Specify a hook function to run on ougtoing and incoming
	// encapsulated T-PDUs. If this hook is non-nil, userspace
	// GTP mode must always be used
	TPDUHook TPDUHook
}

func (cfg *UserPlaneConfig) SetDefaults() {
	if cfg.GTPUTunnel.InterfaceName == "" {
		cfg.GTPUTunnel.InterfaceName = "gtpu_sgw"
	}
	if cfg.GTPUTunnel.MTU == 0 {
		cfg.GTPUTunnel.MTU = 1300
	}
	if cfg.GRXNetNS == nil {
		cfg.GRXNetNS = DefaultNetNS
	}
	if cfg.UENetNS == nil {
		cfg.UENetNS = DefaultNetNS
	}
}

type defaultNetNS struct{}

func (ns defaultNetNS) Handle() netns.NsHandle { return netns.None() }

func (ns defaultNetNS) ListenUDP(ctx context.Context, laddr *net.UDPAddr) (*net.UDPConn, error) {
	// We could use net.ListenConfig's ListenPacket() here to
	// actually use the context, but it only uses the context for
	// laddr lookup which doesn't change things much for us
	return net.ListenUDP("udp", laddr)
}

func (ns defaultNetNS) Do(toCall func() error) error {
	return toCall()
}

var DefaultNetNS NetNS = defaultNetNS{}
