package sgw

import (
	"context"
	"net"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

type KernelTunnel struct {
	tunnelShared
	GTPLink *netlink.GTP
}

func NewKernelTunnel(up *UserPlaneServer, cfg SGWGTPUTunnel) *KernelTunnel {
	kt := &KernelTunnel{
		tunnelShared: newTunnelShared(up, cfg),
	}
	return kt
}

func (kt *KernelTunnel) Start(ctx context.Context) error {
	// remove previous tunnel to clean everything
	if err := kt.cleanup(); err != nil {
		return errors.Wrap(err, "error cleaning up old interfaces")
	}

	f, err := kt.up.s5uConn.File()
	if err != nil {
		return errors.Wrap(err, "Failed to retrieve file from conn")
	}

	kt.GTPLink = &netlink.GTP{
		LinkAttrs: netlink.LinkAttrs{
			Name: kt.cfg.InterfaceName,
		},
		FD1:  int(f.Fd()),
		Role: RoleSGSN,
	}

	if err := kt.up.grxHandle.LinkAdd(kt.GTPLink); err != nil {
		return errors.Wrapf(err, "Failed to add device: %s", kt.GTPLink.Name)
	}

	if err := kt.up.grxHandle.LinkSetUp(kt.GTPLink); err != nil {
		return errors.Wrapf(err, "Failed to setup device: %s", kt.GTPLink.Name)
	}

	if err := kt.up.grxHandle.LinkSetMTU(kt.GTPLink, kt.cfg.MTU); err != nil {
		return errors.Wrapf(err, "Failed to set MTU for device: %s", kt.GTPLink.Name)
	}

	return nil
}

func (kt *KernelTunnel) Close() error {
	if err := kt.cleanup(); err != nil {
		return err
	}

	return nil
}

func (kt *KernelTunnel) RegisterSession(s Session) error {
	if s.IPv4() == nil {
		return errors.New("Missing IPv4 address")
	}

	if s.UNodeAddr().IP == nil {
		return errors.New("Missed unode peer address")
	}

	s.SetTunnelRegistered(true)
	if err := kt.addTunnel(s); err != nil {
		return errors.Wrap(err, "Failed to add tunnel")
	}

	return kt.addRouteAndIPAndRule(s.IPv4(), kt.GTPLink)
}

func (kt *KernelTunnel) HandleTPDU(data []byte, src *net.UDPAddr) error {
	// Because kernel should handle them
	// Even with incorrect teid
	kt.up.logger.Error("HandleTPDU should not happen for KernelTunnel")
	return nil
}
