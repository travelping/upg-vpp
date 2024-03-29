// trafficgen.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"os"

	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/network"
)

type TrafficStats struct {
	ClientSent     int
	ClientReceived int
	ServerSent     int
	ServerReceived int
}

func (s TrafficStats) IsEmpty() bool {
	return s.ClientSent == 0 && s.ClientReceived == 0 &&
		s.ServerSent == 0 && s.ServerReceived == 0
}

type TrafficRec interface {
	RecordError(format string, args ...interface{})
	RecordStats(stats TrafficStats)
	Verify() error
	Stats() TrafficStats
	RecordClientAddr(addr string)
}

type TrafficServer interface {
	Start(ctx context.Context, ns *network.NetNS) error
	Stop()
}

type TrafficClient interface {
	Run(ctx context.Context, ns *network.NetNS) error
}

type TrafficConfig interface {
	SetDefaults()
	AddServerIP(ip net.IP)
	HasServerIP() bool
	SetNoLinger(noLinger bool)
	Server(rec TrafficRec) TrafficServer
	Client(rec TrafficRec) TrafficClient
}

type nullSrv struct{}

func (s nullSrv) Start(ctx context.Context, ns *network.NetNS) error { return nil }

func (s nullSrv) Stop() {}

var nullServer TrafficServer = nullSrv{}

type TrafficGen struct {
	rec TrafficRec
	cfg TrafficConfig
}

func NewTrafficGen(cfg TrafficConfig, rec TrafficRec) *TrafficGen {
	cfg.SetDefaults()
	return &TrafficGen{
		rec: rec,
		cfg: cfg,
	}
}

func (tg *TrafficGen) Run(ctx context.Context, clientNS, serverNS *network.NetNS) error {
	srv := tg.cfg.Server(tg.rec)
	client := tg.cfg.Client(tg.rec)
	if err := srv.Start(ctx, serverNS); err != nil {
		tg.rec.RecordError("starting server: %v", err)
	} else {
		defer srv.Stop()
		if err := client.Run(ctx, clientNS); err != nil {
			tg.rec.RecordError("client error: %v", err)
		}
	}

	stats := tg.rec.Stats()
	if !stats.IsEmpty() {
		logrus.WithFields(logrus.Fields{
			"clientSent":     stats.ClientSent,
			"clientReceived": stats.ClientReceived,
			"serverSent":     stats.ServerSent,
			"serverReceived": stats.ServerReceived,
		}).Debug("traffic stats")
	}

	return tg.rec.Verify()
}

func (tg *TrafficGen) Start(ctx context.Context, clientNS, serverNS *network.NetNS) chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- tg.Run(ctx, clientNS, serverNS)
	}()
	return errCh
}

func quickTest() bool {
	return os.Getenv("UPG_TEST_QUICK") != ""
}
