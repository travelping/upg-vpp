package sgw

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

var ipv6linkLocalUnicastPrefix = []byte{0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

type TunTunnel struct {
	tunnelShared
	tun        *water.Interface
	TUNNetLink netlink.Link
}

func NewTunTunnel(up *UserPlaneServer, cfg SGWGTPUTunnel) *TunTunnel {
	tt := &TunTunnel{
		tunnelShared: newTunnelShared(up, cfg),
	}
	return tt
}

func (tt *TunTunnel) Start(ctx context.Context) error {
	// remove previous tunnel to clean everything
	if err := tt.cleanup(); err != nil {
		return errors.Wrap(err, "error cleaning up old interfaces")
	}

	// XXX: must openDev in the target netns...
	if err := tt.up.cfg.GRXNetNS.Do(func() error {
		if tun, err := water.New(water.Config{
			PlatformSpecificParams: water.PlatformSpecificParams{
				Name: tt.cfg.InterfaceName,
			},
			DeviceType: water.TUN,
		}); err != nil {
			return errors.Wrap(err, "Failed to create tun interface")
		} else {
			tt.tun = tun
			return nil
		}
	}); err != nil {
		return err
	}

	if link, err := tt.up.grxHandle.LinkByName(tt.cfg.InterfaceName); err != nil {
		return errors.Wrapf(err, "Failed to find GTP-U link by name")
	} else {
		link, err = tt.up.moveLinkFromGRXToUE(link)
		if err != nil {
			return errors.Wrap(err, "failed to move GTP-U link to the UE netns")
		}
		tt.TUNNetLink = link
	}

	if err := tt.up.ueHandle.LinkSetUp(tt.TUNNetLink); err != nil {
		return errors.Wrap(err, "Failed to setup device")
	}

	if err := tt.up.ueHandle.LinkSetMTU(tt.TUNNetLink, tt.cfg.MTU); err != nil {
		return errors.Wrap(err, "Failed to set MTU for device")
	}

	go tt.tunnelIncomingRoutine(ctx)

	return nil
}

func (tt *TunTunnel) handleTunnelIncoming(data []byte) {
	var srcIp net.IP
	isipv6 := false

	if waterutil.IsIPv4(data) {
		srcIp = net.IP(data[12:16])
	} else if waterutil.IsIPv6(data) {
		isipv6 = true
		srcIp = net.IP(data[8:24])
	} else {
		tt.up.logger.Warnf("Unknown ip protocol for tunnel packet")
		return
	}

	var s Session
	if isipv6 {
		if bytes.Equal(srcIp[:8], ipv6linkLocalUnicastPrefix) {
			// Ignore link local address of tunnel
			return
		}

		s = tt.up.getSessionByIPv6key(binary.LittleEndian.Uint64(srcIp[8:]))
	} else {
		s = tt.up.getSessionByIPv4key(binary.LittleEndian.Uint32(srcIp))
	}

	if s == nil {
		tt.up.logger.WithField("ue_ip", srcIp).Errorf("Tunnel packet for unknown session")
		return
	}

	if err := tt.up.WriteTo(s.UNodeAddr(), message.NewTPDU(s.TEIDPGWs5u(), data)); err != nil {
		tt.up.logger.WithError(err).Errorf("Failed to write TPDU message")
	}
}

func (tt *TunTunnel) tunnelIncomingRoutine(ctx context.Context) {
	tun := tt.tun
	tt.up.logger.Warn("Started gtp-u tunnel incoming routine")

	for {
		if ctx.Err() != nil {
			return
		}
		buf := make([]byte, 9000)
		if n, err := tun.Read(buf); err != nil {
			if !strings.Contains(err.Error(), "read tun: file already closed") {
				tt.up.logger.WithError(err).Error("Failed to read gtpu tun. Closing tunnel")
			}
			tt.Close()
			return
		} else {
			tt.handleTunnelIncoming(buf[:n])
		}
	}
}

func (tt *TunTunnel) HandleTPDU(data []byte, src *net.UDPAddr) error {
	if _, err := tt.tun.Write(data); err != nil {
		return errors.Wrap(err, "Failed to write in tunnel")
	}
	return nil
}

func (tt *TunTunnel) Close() error {
	if err := tt.tun.Close(); err != nil {
		return errors.Wrap(err, "Failed to close tun device")
	}

	if err := tt.cleanup(); err != nil {
		return err
	}

	return nil
}

func (tt *TunTunnel) RegisterSession(s Session) error {
	s.SetTunnelRegistered(true)

	ip := s.IPv4()
	if ip == nil {
		ip = s.IPv6()
	}
	return tt.addRouteAndIPAndRule(ip, tt.TUNNetLink)
}

func (tt *TunTunnel) UnregisterSession(s Session) error {
	if !s.TunnelRegistered() {
		return nil
	}
	s.SetTunnelRegistered(false)

	ip := s.IPv4()
	if ip == nil {
		ip = s.IPv6()
	}
	return tt.removeRouteAndIPAndRule(ip, tt.TUNNetLink)
}
