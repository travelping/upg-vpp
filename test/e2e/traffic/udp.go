package traffic

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/travelping/upg-vpp/test/e2e/network"
)

const (
	UDP_BUF_SIZE = 1000000
)

type UDPPingConfig struct {
	ServerIP       net.IP
	Port           int
	PacketSize     int
	PacketCount    int
	Timeout        time.Duration
	Retry          bool
	Delay          time.Duration
	NoMTUDiscovery bool
}

var _ TrafficConfig = &UDPPingConfig{}

func (cfg *UDPPingConfig) AddServerIP(ip net.IP) {
	if cfg.ServerIP != nil {
		panic("only single ServerIP is supported")
	}
	cfg.ServerIP = ip
}

func (cfg *UDPPingConfig) SetNoLinger(noLinger bool) {}

func (cfg *UDPPingConfig) SetDefaults() {
	if cfg.Port == 0 {
		cfg.Port = 12345
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 100 * time.Millisecond
	}
	if cfg.PacketSize == 0 {
		cfg.PacketSize = 100
	}
	if cfg.Delay == 0 {
		cfg.Delay = 50 * time.Millisecond
	}
	if cfg.PacketCount == 0 {
		if quickTest() {
			cfg.PacketCount = 40
		} else {
			cfg.PacketCount = 400
		}
	}
}

func (cfg *UDPPingConfig) Server(rec TrafficRec) TrafficServer {
	return &UDPServer{rec: rec, cfg: *cfg}
}
func (cfg *UDPPingConfig) Client(rec TrafficRec) TrafficClient {
	return &UDPPing{rec: rec, cfg: *cfg}
}

type UDPServer struct {
	rec    TrafficRec
	cfg    UDPPingConfig
	cancel context.CancelFunc
}

var _ TrafficServer = &UDPServer{}

func (us *UDPServer) Stop() {
	if us.cancel != nil {
		us.cancel()
		us.cancel = nil
	}
}

func (us *UDPServer) Start(ctx context.Context, ns *network.NetNS) error {
	if us.cfg.PacketSize == 0 {
		panic("zero chunk size")
	}

	uc, err := ns.ListenUDP(ctx, &net.UDPAddr{
		IP:   nil,
		Port: us.cfg.Port,
	})
	if err != nil {
		return errors.Wrap(err, "ListenTCP")
	}

	if us.cfg.NoMTUDiscovery {
		uc, err = noMTUDiscovery(uc)
		if err != nil {
			return errors.Wrap(err, "disabling MTU discovery")
		}
	}

	childCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-childCtx.Done():
			// stop ReadFromUDP by closing the conn
			// if it is active now
			uc.Close()
		}
	}()
	us.cancel = cancel

	buf := make([]byte, UDP_BUF_SIZE)
	go func() {
		// this will cause the conn to be closed
		defer cancel()
		for {
			n, addr, err := uc.ReadFromUDP(buf)
			if err != nil {
				// TODO: do errors.Is(err, net.ErrClosed) check to see if
				// we have a error here after switching
				// to newer Go version that has net.ErrClosed
				return
			}
			us.rec.RecordStats(TrafficStats{ServerReceived: n})

			if n != us.cfg.PacketSize {
				us.rec.RecordError("bad udp packet size: %d instead of %d", n, us.cfg.PacketSize)
			} else {
				buf[0] = '<'
			}

			if _, err := uc.WriteTo(buf[0:n], addr); err != nil {
				us.rec.RecordError("udp send: %v", err)
			} else {
				us.rec.RecordStats(TrafficStats{ServerSent: n})
			}
		}
	}()

	return nil
}

type UDPPing struct {
	rec TrafficRec
	cfg UDPPingConfig
}

var _ TrafficClient = &UDPPing{}

func (up *UDPPing) genUDPPacket(n int, buf []byte) {
	buf[0] = '>'
	if len(buf) > 1 {
		s := strconv.Itoa(n)
		j := len(s) - 1
		for i := len(buf) - 1; i > 0; i-- {
			if j >= 0 {
				buf[i] = s[j]
				j--
			} else {
				buf[i] = '0'
			}
		}
	}
}

func (up *UDPPing) Run(ctx context.Context, ns *network.NetNS) error {
	if up.cfg.PacketSize == 0 {
		return errors.New("zero chunk size")
	}

	c, err := ns.DialUDP(
		ctx,
		nil,
		&net.UDPAddr{
			IP:   up.cfg.ServerIP,
			Port: up.cfg.Port,
		})
	if err != nil {
		return errors.Wrap(err, "DialUDP")
	}

	if up.cfg.NoMTUDiscovery {
		c, err = noMTUDiscovery(c)
		if err != nil {
			return errors.Wrap(err, "disabling MTU discovery")
		}
	}

	childCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-childCtx.Done():
			// stop ReadFromUDP by closing the conn
			// if it is active now
			c.Close()
		}
	}()

	// this will cause the conn to be closed
	defer cancel()

	sendBuf := make([]byte, up.cfg.PacketSize)
	recvBuf := make([]byte, up.cfg.PacketSize)
	for i := 0; i < up.cfg.PacketCount; i++ {
		up.genUDPPacket(i, sendBuf)
		if _, err := c.Write(sendBuf); err != nil {
			return errors.Wrap(err, "udp send")
		}
		up.rec.RecordStats(TrafficStats{ClientSent: len(sendBuf)})
		c.SetReadDeadline(time.Now().Add(up.cfg.Timeout))
		n, _, err := c.ReadFromUDP(recvBuf)
		if err != nil {
			if !up.cfg.Retry {
				return errors.Wrap(err, "udp receive")
			}
		} else {
			up.rec.RecordStats(TrafficStats{ClientReceived: n})
			if n != len(sendBuf) {
				up.rec.RecordError("recv length mismatch: %d instead of %d bytes: %q", n, len(sendBuf), string(recvBuf[:n]))
				continue
			}
			// in case if retries are enabled
			if !up.cfg.Retry && (recvBuf[0] != '<' || string(recvBuf[1:]) != string(sendBuf[1:])) {
				up.rec.RecordError("recv mismatch: response %q for request %q", string(recvBuf), string(sendBuf))
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(up.cfg.Delay):
		}
	}

	return nil
}
