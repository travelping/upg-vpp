package traffic

import (
	"context"
	"net"
	"time"

	"github.com/go-ping/ping"
	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/network"
)

type ICMPPingConfig struct {
	ServerIP    net.IP
	PacketSize  int
	PacketCount int
	Timeout     time.Duration
	Retry       bool
	Delay       time.Duration
}

var _ TrafficConfig = &ICMPPingConfig{}

func (cfg *ICMPPingConfig) SetServerIP(ip net.IP)     { cfg.ServerIP = ip }
func (cfg *ICMPPingConfig) SetNoLinger(noLinger bool) {}

func (cfg *ICMPPingConfig) SetDefaults() {
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

func (cfg *ICMPPingConfig) Server(rec TrafficRec) TrafficServer { return nullServer }

func (cfg *ICMPPingConfig) Client(rec TrafficRec) TrafficClient {
	return &ICMPPing{rec: rec, cfg: cfg}
}

type ICMPPing struct {
	rec TrafficRec
	cfg *ICMPPingConfig
	log *logrus.Entry
}

var _ TrafficClient = &ICMPPing{}

func (p *ICMPPing) Run(ctx context.Context, ns *network.NetNS) error {
	return ns.Do(func() error {
		pinger := ping.New("")
		pinger.SetIPAddr(&net.IPAddr{
			IP: p.cfg.ServerIP,
		})
		pinger.SetPrivileged(true)
		pinger.Count = p.cfg.PacketCount
		pinger.Size = p.cfg.PacketSize
		pinger.OnSend = func(pkt *ping.Packet) {
			p.rec.RecordStats(TrafficStats{ClientSent: pkt.Nbytes})
		}
		pinger.OnRecv = func(pkt *ping.Packet) {
			p.rec.RecordStats(TrafficStats{
				// FIXME: this is kind of unpretty
				ClientReceived: pkt.Nbytes,
				ServerReceived: pkt.Nbytes,
				ServerSent:     pkt.Nbytes})
		}

		childCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			<-childCtx.Done()
			pinger.Stop()
		}()

		return pinger.Run()
	})
}
