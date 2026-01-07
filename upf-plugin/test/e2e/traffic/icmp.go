// icmp.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	SourceIP net.IP
	ServerIP net.IP

	PacketSize       int
	PacketCount      int
	Timeout          time.Duration
	Delay            time.Duration
	StopOnFirstReply bool
}

var _ TrafficConfig = &ICMPPingConfig{}

func (cfg *ICMPPingConfig) AddServerIP(ip net.IP) {
	if cfg.ServerIP != nil {
		panic("only single ServerIP is supported")
	}
	cfg.ServerIP = ip
}

func (cfg *ICMPPingConfig) HasServerIP() bool {
	return cfg.ServerIP != nil
}

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
		if p.cfg.SourceIP != nil {
			pinger.Source = p.cfg.SourceIP.String()
		}
		pinger.SetPrivileged(true)
		pinger.Count = p.cfg.PacketCount
		pinger.Size = p.cfg.PacketSize
		pinger.Interval = p.cfg.Delay
		pinger.Timeout = time.Duration(pinger.Count)*pinger.Interval + 3*time.Second

		pinger.OnSend = func(pkt *ping.Packet) {
			p.rec.RecordStats(TrafficStats{ClientSent: pkt.Nbytes})
		}
		pinger.OnRecv = func(pkt *ping.Packet) {
			p.rec.RecordStats(TrafficStats{
				// FIXME: this is kind of unpretty
				ClientReceived: pkt.Nbytes,
				ServerReceived: pkt.Nbytes,
				ServerSent:     pkt.Nbytes})

			if p.cfg.StopOnFirstReply {
				pinger.Stop()
			}
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
