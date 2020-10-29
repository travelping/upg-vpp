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

	movedLink, err := kt.up.moveLinkFromUEToGRX(kt.GTPLink)
	if err != nil {
		return errors.Wrap(err, "error moving GTP link back to the GRX netns")
	}
	kt.GTPLink = movedLink.(*netlink.GTP)

	if pdp, err := kt.up.grxHandle.GTPPDPByITEI(kt.GTPLink, int(s.TEIDSGWs5u())); err != nil {
		return errors.Wrap(err, "Failed to get tunnel by ITEI")
	} else {
		if err := kt.up.grxHandle.GTPPDPDel(kt.GTPLink, pdp); err != nil {
			return errors.Wrap(err, "Failed to delete gtp tunnel")
		}
	}

	return kt.removeRouteAndIPAndRule(s.IPv4(), kt.GTPLink)
}

func (kt *KernelTunnel) addTunnel(s Session) error {
	// Remove already existing tunnel
	if pdp, _ := kt.up.grxHandle.GTPPDPByMSAddress(kt.GTPLink, s.UNodeAddr().IP); pdp != nil {
		s.Logger().Warn("Registering session against already existing gtpu netlink by MSAddress")
		kt.up.grxHandle.GTPPDPDel(kt.GTPLink, pdp)
	}
	if pdp, _ := kt.up.grxHandle.GTPPDPByITEI(kt.GTPLink, int(s.TEIDSGWs5u())); pdp != nil {
		s.Logger().Warn("Registering session against already existing gtpu netlink by ITEI")
		kt.up.grxHandle.GTPPDPDel(kt.GTPLink, pdp)
	}

	pdp := &netlink.PDP{
		Version:     1,
		PeerAddress: s.UNodeAddr().IP,
		MSAddress:   s.IPv4(),
		OTEI:        s.TEIDPGWs5u(),
		ITEI:        s.TEIDSGWs5u(),
	}
	if err := kt.up.grxHandle.GTPPDPAdd(kt.GTPLink, pdp); err != nil {
		return errors.Wrap(err, "Failed to add gtp tunnel")
	}

	movedLink, err := kt.up.moveLinkFromGRXToUE(kt.GTPLink)
	if err != nil {
		return errors.Wrap(err, "error moving GTP link to the UE netns")
	}
	kt.GTPLink = movedLink.(*netlink.GTP)

	return nil
}
