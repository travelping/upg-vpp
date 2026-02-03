// uplane.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"net/netip"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-gtp/gtpv1/message"
	"gopkg.in/tomb.v2"
)

const (
	GTPU_PORT = 2152
)

type UserPlaneTunnel interface {
	Start(context.Context) error
	Close() error
	RegisterSession(s Session) error
	UnregisterSession(s Session) error
	HandleTPDU(data []byte, src *net.UDPAddr) error
}

type UserPlaneServer struct {
	mu sync.RWMutex

	cfg UserPlaneConfig

	s5uAddr net.UDPAddr
	s5uConn *net.UDPConn

	tunnel UserPlaneTunnel

	sgwUTEIDtoSessionMap map[uint32]Session
	ueIPtoSessionMap     map[netip.Addr]Session
	endMarkersCh         chan uint32
	errorIndicationCh    chan message.ErrorIndication

	restartCounter uint8

	logger *logrus.Entry

	grxHandle *netlink.Handle
	ueHandle  *netlink.Handle

	t *tomb.Tomb
}

func NewUserPlaneServer(cfg UserPlaneConfig, restartCounter uint8) (up *UserPlaneServer, err error) {
	up = &UserPlaneServer{
		cfg:                  cfg,
		s5uAddr:              net.UDPAddr{IP: cfg.S5uIP, Port: GTPU_PORT},
		logger:               logrus.WithField("sgwuip", cfg.S5uIP),
		sgwUTEIDtoSessionMap: make(map[uint32]Session),
		ueIPtoSessionMap:     make(map[netip.Addr]Session),
		restartCounter:       restartCounter,
		endMarkersCh:         make(chan uint32, 32),
		errorIndicationCh:    make(chan message.ErrorIndication, 32),
	}

	if cfg.S5uIP.To4() == nil {
		// BUG: somehow, ListenUDP may fail if we try to pass
		// it an IPv6 address. This has been observed while
		// using separate network namespaces for SGW/UE:
		// 'listen udp [2001:db8:13::3]:2152: bind: cannot assign requested address'
		// despite [2001:db8:13::3]:2152 being available in that
		// netns. With no IP provided, ListenUDP works as expected
		// (listens on [::]:2152)
		up.s5uAddr.IP = net.IPv6zero
	}

	up.cfg.SetDefaults()

	up.grxHandle, err = netlink.NewHandleAt(cfg.GRXNetNS.Handle())
	if err != nil {
		return nil, errors.Wrap(err, "can't create GRX netns handle")
	}

	up.ueHandle, err = netlink.NewHandleAt(cfg.UENetNS.Handle())
	if err != nil {
		return nil, errors.Wrap(err, "can't create UE netns handle")
	}

	switch cfg.GTPUTunnel.Type {
	case SGWGTPUTunnelTypeTun:
		up.tunnel = NewTunTunnel(up, cfg.GTPUTunnel)
	case SGWGTPUTunnelTypeNone:
		up.tunnel = nil
	default:
		return nil, errors.Errorf("Unknown tunnel type %q", cfg.GTPUTunnel.Type)
	}
	return up, nil
}

func (up *UserPlaneServer) Start(ctx context.Context) error {
	if up.t != nil {
		return nil
	}

	conn, err := up.cfg.GRXNetNS.ListenUDP(context.Background(), &up.s5uAddr)
	if err != nil {
		return err
	}
	up.s5uConn = conn

	if up.tunnel != nil {
		if err := up.tunnel.Start(ctx); err != nil {
			return errors.Wrap(err, "Failed to start user-plane tunnel")
		}
	}

	up.t, _ = tomb.WithContext(ctx)
	up.t.Go(up.listenLoop)
	return nil
}

func (up *UserPlaneServer) handlePacket(buf []byte, src *net.UDPAddr) {
	msg, err := message.Parse(buf)
	if err != nil {
		up.logger.WithError(err).Error("Failed to parse gtpu message")
	}

	if err := up.handleMessage(msg, src); err != nil {
		up.logger.WithError(err).Errorf("Failed to handle gtpu message %T", msg)
	}
}

func (up *UserPlaneServer) Stop() error {
	if up.t == nil {
		return nil
	}

	up.logger.Info("Stopping sgw-u server")

	up.t.Kill(nil)
	if up.s5uConn != nil {
		up.s5uConn.Close()
	}

	if up.tunnel != nil {
		up.tunnel.Close()
	}
	err := up.t.Wait()
	up.t = nil
	return err
}

func (up *UserPlaneServer) listenLoop() error {
	up.logger.Info("Listening on s5u interface")
	defer up.logger.Info("SGW-U server stopped")

	listenConn := up.s5uConn
	defer listenConn.Close()

	for {
		select {
		case <-up.t.Dying():
			return nil
		default:
			buffer := make([]byte, 9000)
			n, src, err := listenConn.ReadFromUDP(buffer)
			if err != nil {
				// sadly even internal http2 lib parses these errors this way
				if !strings.Contains(err.Error(), "use of closed network connection") {
					up.logger.WithError(err).Error("Failed to read from UDP connection")
					return errors.Wrap(err, "Failed to read from UDP connection")
				}
				return nil
			}

			up.handlePacket(buffer[:n], src)
		}
	}
}

func (up *UserPlaneServer) RegisterSession(s Session) error {
	s.Logger().WithField("ip4", s.IPv4()).WithField("ip6", s.IPv6()).Debug("Registered unode session")

	up.mu.Lock()
	defer up.mu.Unlock()

	up.sgwUTEIDtoSessionMap[s.TEIDSGWs5u()] = s
	if s.IPv4() != nil {
		k, _ := netip.AddrFromSlice(s.IPv4().To4())
		up.ueIPtoSessionMap[k] = s
	}
	if s.IPv6() != nil {
		k, _ := netip.AddrFromSlice(s.IPv6())
		up.ueIPtoSessionMap[k] = s
	}

	if up.tunnel != nil {
		if err := up.tunnel.RegisterSession(s); err != nil {
			s.Logger().WithError(err).Error("Failed to add tunnel")
			return err
		} else {
			s.Logger().Debug("Tunnel added")
		}
		s.TriggerEvent(&SessionTunnelStartEvent{})
	}

	return nil
}

func (up *UserPlaneServer) UnRegisterSession(s Session) error {
	s.Logger().WithField("ip4", s.IPv4()).WithField("ip6", s.IPv6()).Debug("UnRegistered unode session")

	up.mu.Lock()
	defer up.mu.Unlock()

	if oldS, ex := up.sgwUTEIDtoSessionMap[s.TEIDSGWs5u()]; ex && oldS == s {
		delete(up.sgwUTEIDtoSessionMap, s.TEIDSGWs5u())
	}

	if s.IPv4() != nil {
		k, _ := netip.AddrFromSlice(s.IPv4().To4())
		if oldS, ex := up.ueIPtoSessionMap[k]; ex && oldS == s {
			delete(up.ueIPtoSessionMap, k)
		}
	}
	if s.IPv6() != nil {
		k, _ := netip.AddrFromSlice(s.IPv6())
		if oldS, ex := up.ueIPtoSessionMap[k]; ex && oldS == s {
			delete(up.ueIPtoSessionMap, k)
		}
	}

	if up.tunnel != nil {
		s.TriggerEvent(&SessionTunnelStopEvent{})

		if err := up.tunnel.UnregisterSession(s); err != nil {
			s.Logger().WithError(err).Error("Failed to remove tunnel")
			return err
		} else {
			s.Logger().Debug("Tunnel removed")
		}
	}

	return nil
}

func (up *UserPlaneServer) WriteTo(dstAddr *net.UDPAddr, toBeSentMsg message.Message) error {
	payload, err := message.Marshal(toBeSentMsg)
	if err != nil {
		return errors.Wrapf(err, "Failed to marshal payload %T", toBeSentMsg)
	}
	if up.cfg.GTPURawHook != nil {
		payload = up.cfg.GTPURawHook(payload)
	}

	if _, err := up.s5uConn.WriteToUDP(payload, dstAddr); err != nil {
		return errors.Wrapf(err, "Failed to send %T", toBeSentMsg)
	}
	return nil
}

func (up *UserPlaneServer) SendResponse(dstAddr *net.UDPAddr, receivedMsg, toBeSentMsg message.Message) error {
	up.logger.Tracef("Sending response %T on %T", toBeSentMsg, receivedMsg)
	toBeSentMsg.SetSequenceNumber(receivedMsg.Sequence())

	return up.WriteTo(dstAddr, toBeSentMsg)
}

func (up *UserPlaneServer) getSessionBySTEID(teid uint32) Session {
	up.mu.RLock()
	defer up.mu.RUnlock()
	if s, ok := up.sgwUTEIDtoSessionMap[teid]; !ok {
		return nil
	} else {
		return s
	}
}

func (up *UserPlaneServer) getSessionByIP(ip netip.Addr) Session {
	up.mu.RLock()
	defer up.mu.RUnlock()
	if s, ok := up.ueIPtoSessionMap[ip]; !ok {
		return nil
	} else {
		return s
	}
}

func (up *UserPlaneServer) moveLinkFromGRXToUE(link netlink.Link) (netlink.Link, error) {
	if up.cfg.UENetNS == DefaultNetNS {
		return link, nil
	}

	if err := up.grxHandle.LinkSetNsFd(link, int(up.cfg.UENetNS.Handle())); err != nil {
		return nil, errors.Wrapf(err, "failed to move link %s to GRX netns", link.Attrs().Name)
	}

	movedLink, err := up.ueHandle.LinkByName(link.Attrs().Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find link %s after moving to GRX netns", link.Attrs().Name)
	}

	return movedLink, nil
}

func (up *UserPlaneServer) moveLinkFromUEToGRX(link netlink.Link) (netlink.Link, error) {
	if up.cfg.UENetNS == DefaultNetNS {
		return link, nil
	}

	if err := up.ueHandle.LinkSetNsFd(link, int(up.cfg.GRXNetNS.Handle())); err != nil {
		return nil, errors.Wrapf(err, "failed to move link %s to GRX netns", link.Attrs().Name)
	}

	movedLink, err := up.grxHandle.LinkByName(link.Attrs().Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find link %s after moving to GRX netns", link.Attrs().Name)
	}

	return movedLink, nil
}

func (up *UserPlaneServer) Context(parent context.Context) context.Context {
	if up.t == nil {
		panic("UserPlaneServer not started")
	}
	return up.t.Context(parent)
}

func (up *UserPlaneServer) EndMarkersCh() <-chan uint32 {
	return up.endMarkersCh
}

func (up *UserPlaneServer) ErrorIndicationCh() <-chan message.ErrorIndication {
	return up.errorIndicationCh
}
