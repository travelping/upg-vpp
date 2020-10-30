package sgw

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-gtp/gtpv1/message"
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

	lastSequenceNumber uint32
	tunnel             UserPlaneTunnel

	sgwUTEIDtoSessionMap map[uint32]Session
	ueIPv4toSessionMap   map[uint32]Session
	// ipv6 map counts only last 64 bits of ipv6 address
	// because it's cheaper for golang than trying to handle 128bit's keys
	ueIPv6toSessionMap map[uint64]Session

	restartCounter uint8

	logger  *logrus.Entry
	closeCh chan struct{}
	err     error

	grxHandle *netlink.Handle
	ueHandle  *netlink.Handle
}

func NewUserPlaneServer(cfg UserPlaneConfig, restartCounter uint8) (up *UserPlaneServer, err error) {
	up = &UserPlaneServer{
		cfg:                  cfg,
		s5uAddr:              net.UDPAddr{IP: cfg.S5uIP, Port: GTPU_PORT},
		logger:               logrus.WithField("sgwuip", cfg.S5uIP),
		closeCh:              make(chan struct{}),
		sgwUTEIDtoSessionMap: make(map[uint32]Session),
		ueIPv4toSessionMap:   make(map[uint32]Session),
		ueIPv6toSessionMap:   make(map[uint64]Session),
		restartCounter:       restartCounter,
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
	case SGWGTPUTunnelTypeKernel:
		up.tunnel = NewKernelTunnel(up, cfg.GTPUTunnel)
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
	conn, err := up.cfg.GRXNetNS.ListenUDP(&up.s5uAddr)
	if err != nil {
		return err
	}
	up.s5uConn = conn

	if up.tunnel != nil {
		if err := up.tunnel.Start(ctx); err != nil {
			return errors.Wrap(err, "Failed to start user-plane tunnel")
		}
	}

	go up.listenRoutine(ctx)
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

func (up *UserPlaneServer) Stop(err error) error {
	up.mu.Lock()
	defer up.mu.Unlock()

	select {
	case <-up.closeCh:
		return up.err
	default:
	}

	if err != nil {
		up.logger.WithError(err).Warn("Stopping sgw-u server")
	} else {
		up.logger.WithError(err).Info("Stopping sgw-u server")
	}

	up.err = err
	if up.s5uConn != nil {
		up.s5uConn.Close()
	}
	close(up.closeCh)

	if up.tunnel != nil {
		up.tunnel.Close()
	}

	return up.err
}

func (up *UserPlaneServer) listenRoutine(ctx context.Context) {
	up.logger.Warn("Listening on s5u interface")

	listenConn := up.s5uConn
	defer listenConn.Close()

	for {
		select {
		case <-up.closeCh:
			return
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, 9000)
			n, src, err := listenConn.ReadFromUDP(buffer)
			if err != nil {
				// sadly even internal http2 lib parses these errors this way
				if !strings.Contains(err.Error(), "use of closed network connection") {
					up.logger.WithError(err).Error("Failed to read from UDP connection")
				}
				wrappedErr := errors.Wrapf(err, "Failed to read from UDP connection")
				up.Stop(wrappedErr)
				return
			}

			up.handlePacket(buffer[:n], src)
		}
	}
}

func (up *UserPlaneServer) Done() <-chan struct{} { return up.closeCh }

func upIpv4KeyForSession(s Session) uint32 { return binary.LittleEndian.Uint32(s.IPv4().To4()) }
func upIpv6KeyForSession(s Session) uint64 { return binary.LittleEndian.Uint64(s.IPv6()[8:]) }

func (up *UserPlaneServer) RegisterSession(s Session) error {
	s.Logger().WithField("ip4", s.IPv4()).WithField("ip6", s.IPv6()).Debug("Registered unode session")

	up.mu.Lock()
	defer up.mu.Unlock()

	up.sgwUTEIDtoSessionMap[s.TEIDSGWs5u()] = s
	if s.IPv4() != nil {
		up.ueIPv4toSessionMap[upIpv4KeyForSession(s)] = s
	}
	if s.IPv6() != nil {
		up.ueIPv6toSessionMap[upIpv6KeyForSession(s)] = s
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
		ipv4key := upIpv4KeyForSession(s)
		if oldS, ex := up.ueIPv4toSessionMap[ipv4key]; ex && oldS == s {
			delete(up.ueIPv4toSessionMap, ipv4key)
		}
	}
	if s.IPv6() != nil {
		ipv6key := upIpv6KeyForSession(s)
		if oldS, ex := up.ueIPv6toSessionMap[ipv6key]; ex && oldS == s {
			delete(up.ueIPv6toSessionMap, ipv6key)
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

func (up *UserPlaneServer) getSessionByIPv4key(ipv4key uint32) Session {
	up.mu.RLock()
	defer up.mu.RUnlock()
	if s, ok := up.ueIPv4toSessionMap[ipv4key]; !ok {
		return nil
	} else {
		return s
	}
}

func (up *UserPlaneServer) getSessionByIPv6key(ipv6key uint64) Session {
	up.mu.RLock()
	defer up.mu.RUnlock()
	if s, ok := up.ueIPv6toSessionMap[ipv6key]; !ok {
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
