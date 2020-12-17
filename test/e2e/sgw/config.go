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
	InterfaceName string            `yaml:"interface_name",default:"gtpu_sgw"`
	MTU           int               `yaml:"mtu",default:"1300"`
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
