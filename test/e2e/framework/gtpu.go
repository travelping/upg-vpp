// gtpu.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package framework

import (
	"context"
	"net"
	"os"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-gtp/gtpv1/ie"
	"github.com/wmnsk/go-gtp/gtpv1/message"

	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/network"
	"github.com/travelping/upg-vpp/test/e2e/sgw"
)

type TPDUHook sgw.TPDUHook

type GTPUConfig struct {
	GRXNS      *network.NetNS
	UENS       *network.NetNS
	UEIP       net.IP
	SGWIP      net.IP
	PGWIP      net.IP
	TEIDPGWs5u uint32
	TEIDSGWs5u uint32
	LinkName   string
	MTU        int
	TPDUHook   TPDUHook
}

func (cfg GTPUConfig) ipv6() bool {
	return cfg.UEIP.To4() == nil || cfg.SGWIP.To4() == nil || cfg.PGWIP.To4() == nil
}

func (cfg GTPUConfig) gtpuTunnelType() sgw.SGWGTPUTunnelType {
	// if TPDUHook is used, we must use userspace GTP-U
	// TODO: autodetect kernel GTP-U support
	if cfg.TPDUHook == nil && !cfg.ipv6() && os.Getenv("UPG_TEST_GTPU_KERNEL") != "" {
		return sgw.SGWGTPUTunnelTypeKernel
	}

	return sgw.SGWGTPUTunnelTypeTun
}

func (cfg *GTPUConfig) SetDefaults() {
	if cfg.MTU == 0 {
		cfg.MTU = 1300
	}
}

type GTPU struct {
	cfg     GTPUConfig
	up      *sgw.UserPlaneServer
	session *sgw.SimpleSession
}

func NewGTPU(cfg GTPUConfig) (*GTPU, error) {
	cfg.SetDefaults()
	up, err := sgw.NewUserPlaneServer(sgw.UserPlaneConfig{
		S5uIP: cfg.SGWIP,
		GTPUTunnel: sgw.SGWGTPUTunnel{
			Type:          cfg.gtpuTunnelType(),
			InterfaceName: cfg.LinkName,
			MTU:           cfg.MTU,
		},
		GRXNetNS: cfg.GRXNS,
		UENetNS:  cfg.UENS,
		TPDUHook: sgw.TPDUHook(cfg.TPDUHook),
	}, 0)
	if err != nil {
		return nil, errors.Wrap(err, "error creating the user plane server")
	}
	return &GTPU{
		cfg: cfg,
		up:  up,
	}, nil
}

func (gtpu *GTPU) Start(ctx context.Context) error {
	if gtpu.session != nil {
		return nil
	}

	var ueIPv4, ueIPv6 net.IP
	if gtpu.cfg.UEIP.To4() == nil {
		ueIPv6 = gtpu.cfg.UEIP
	} else {
		ueIPv4 = gtpu.cfg.UEIP
	}

	logrus.SetLevel(logrus.DebugLevel)

	if err := gtpu.up.Start(ctx); err != nil {
		return errors.Wrap(err, "error starting GTPU")
	}

	session := sgw.NewSimpleSession(sgw.SimpleSessionConfig{
		UNodeAddr: &net.UDPAddr{
			IP:   gtpu.cfg.PGWIP,
			Port: sgw.GTPU_PORT,
		},
		TEIDPGWs5u: gtpu.cfg.TEIDPGWs5u,
		TEIDSGWs5u: gtpu.cfg.TEIDSGWs5u,
		IPv4:       ueIPv4,
		IPv6:       ueIPv6,
		// FIXME: use proper logger
		Logger: logrus.NewEntry(logrus.StandardLogger()),
	})

	if err := gtpu.up.RegisterSession(session); err != nil {
		gtpu.up.Stop()
		return errors.Wrap(err, "failed to register GTPU session")
	}

	gtpu.session = session
	gtpu.cfg.GRXNS.AddCleanup(func() { gtpu.Stop() })

	return nil
}

func (gtpu *GTPU) Stop() error {
	if gtpu.session == nil {
		return nil
	}

	if err := gtpu.up.UnRegisterSession(gtpu.session); err != nil {

		gtpu.up.Stop()
		return errors.Wrap(err, "error unregistering the session")
	}

	return gtpu.up.Stop()
}

func (gtpu *GTPU) SendErrorIndication(teid uint32, seq uint16, IEs ...*ie.IE) error {
	dst := net.UDPAddr{
		IP:   gtpu.cfg.PGWIP,
		Port: 2152,
	}
	return gtpu.up.WriteTo(&dst, message.NewErrorIndication(teid, seq, IEs...))
}

func (gtpu *GTPU) Context(parent context.Context) context.Context {
	return gtpu.up.Context(parent)
}
