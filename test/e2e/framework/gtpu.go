package framework

import (
	"context"
	"net"
	"os"

	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"

	"github.com/travelping/upg-vpp/test/e2e/network"
	"github.com/travelping/upg-vpp/test/e2e/sgw"
)

type GTPUConfig struct {
	GRXNS      *network.NetNS
	UENS       *network.NetNS
	UEIP       net.IP
	SGWGRXIP   net.IP
	PGWGRXIP   net.IP
	TEIDPGWs5u uint32
	TEIDSGWs5u uint32
	LinkName   string
	MTU        int
}

func (cfg GTPUConfig) ipv6() bool {
	return cfg.UEIP.To4() == nil || cfg.SGWGRXIP.To4() == nil || cfg.PGWGRXIP.To4() == nil
}

func (cfg GTPUConfig) gtpuTunnelType() sgw.SGWGTPUTunnelType {
	// TODO: autodetect kernel GTP-U support
	if !cfg.ipv6() && os.Getenv("UPG_TEST_GTPU_KERNEL") != "" {
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
		S5uIP: cfg.SGWGRXIP,
		GTPUTunnel: sgw.SGWGTPUTunnel{
			Type:          cfg.gtpuTunnelType(),
			InterfaceName: cfg.LinkName,
			MTU:           cfg.MTU,
		},
		GRXNetNS: cfg.GRXNS,
		UENetNS:  cfg.UENS,
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
			IP:   gtpu.cfg.PGWGRXIP,
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

func (gtpu *GTPU) Context(parent context.Context) context.Context {
	return gtpu.up.Context(parent)
}
