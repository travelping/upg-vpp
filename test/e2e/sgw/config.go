package sgw

import (
	"net"

	"github.com/vishvananda/netns"
)

type SGWGTPUTunnelType string

const (
	SGWGTPUTunnelTypeNone   SGWGTPUTunnelType = ""
	SGWGTPUTunnelTypeKernel SGWGTPUTunnelType = "kernel"
	SGWGTPUTunnelTypeTun    SGWGTPUTunnelType = "tun"
)

type NetNS interface {
	Handle() netns.NsHandle
	ListenUDP(laddr *net.UDPAddr) (*net.UDPConn, error)
	Do(toCall func() error) error
}

type SGWGTPUTunnel struct {
	Type          SGWGTPUTunnelType `yaml:"type"`
	InterfaceName string            `yaml:"interface_name",default:"gtpu_sgw"`
	MTU           int               `yaml:"mtu",default:"1300"`
}

type UserPlaneConfig struct {
	S5uIP      net.IP
	GTPUTunnel SGWGTPUTunnel
	GRXNetNS   NetNS
	UENetNS    NetNS
	AddRule    bool
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

func (ns defaultNetNS) ListenUDP(laddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP("udp", laddr)
}

func (ns defaultNetNS) Do(toCall func() error) error {
	return toCall()
}

var DefaultNetNS NetNS = defaultNetNS{}
