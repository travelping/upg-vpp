// +build linux

package sgw

import (
	"github.com/pkg/errors"

	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-gtp/gtpv1"
)

const (
	RoleSGSN   = int(gtpv1.RoleSGSN)
	SCOPE_LINK = netlink.SCOPE_LINK
	FAMILY_ALL = netlink.FAMILY_ALL
)

func (kt *KernelTunnel) UnregisterSession(s Session) error {
	if !s.TunnelRegistered() {
		return nil
	}
	s.SetTunnelRegistered(false)

	if err := kt.up.cfg.UENetNS.Do(func() error {
		if pdp, err := kt.up.ueHandle.GTPPDPByITEI(kt.GTPLink, int(s.TEIDSGWs5u())); err != nil {
			return errors.Wrap(err, "Failed to get tunnel by ITEI")
		} else {
			if err := kt.up.ueHandle.GTPPDPDel(kt.GTPLink, pdp); err != nil {
				return errors.Wrap(err, "Failed to delete gtp tunnel")
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return kt.removeRouteAndIPAndRule(s.IPv4(), kt.GTPLink)
}

func (kt *KernelTunnel) addTunnel(s Session) error {
	kt.up.logger.WithField("GTPLink", kt.GTPLink.Name).Debug("addTunnel")

	if err := kt.up.cfg.UENetNS.Do(func() error {
		// Remove already existing tunnel
		if pdp, _ := kt.up.ueHandle.GTPPDPByMSAddress(kt.GTPLink, s.UNodeAddr().IP); pdp != nil {
			s.Logger().Warn("Registering session against already existing gtpu netlink by MSAddress")
			kt.up.ueHandle.GTPPDPDel(kt.GTPLink, pdp)
		}
		if pdp, _ := kt.up.ueHandle.GTPPDPByITEI(kt.GTPLink, int(s.TEIDSGWs5u())); pdp != nil {
			s.Logger().Warn("Registering session against already existing gtpu netlink by ITEI")
			kt.up.ueHandle.GTPPDPDel(kt.GTPLink, pdp)
		}
		return nil
	}); err != nil {
		return err
	}

	pdp := &netlink.PDP{
		Version:     1,
		PeerAddress: s.UNodeAddr().IP.To4(),
		MSAddress:   s.IPv4().To4(),
		OTEI:        s.TEIDPGWs5u(),
		ITEI:        s.TEIDSGWs5u(),
	}

	if err := kt.up.cfg.GRXNetNS.Do(func() error {
		return kt.up.grxHandle.GTPPDPAdd(kt.GTPLink, pdp)
	}); err != nil {
		return errors.Wrap(err, "Failed to add gtp tunnel")
	}

	movedLink, err := kt.up.moveLinkFromGRXToUE(kt.GTPLink)
	if err != nil {
		return errors.Wrap(err, "error moving GTP link to the UE netns")
	}
	kt.GTPLink = movedLink.(*netlink.GTP)

	if err := kt.up.ueHandle.LinkSetUp(kt.GTPLink); err != nil {
		return errors.Wrapf(err, "Failed to setup device: %s", kt.GTPLink.Name)
	}

	return nil
}
