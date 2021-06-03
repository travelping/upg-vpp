package framework

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/travelping/upg-vpp/test/e2e/pfcp"
)

type SessionConfig struct {
	IdBase          uint16
	UEIP            net.IP
	PGWIP           net.IP
	SGWIP           net.IP
	AppName         string
	Redirect        bool
	Mode            UPGMode
	TEIDPGWs5u      uint32
	TEIDSGWs5u      uint32
	ProxyAccessIP   net.IP
	ProxyCoreIP     net.IP
	ProxyAccessTEID uint32
	ProxyCoreTEID   uint32
	NoURRs          bool
}

const (
	HTTPAppName = "TST"
	IPAppName   = "IPAPP"
)

func (cfg SessionConfig) sgwOuterHeaderCreation() *ie.IE {
	ip4 := cfg.SGWIP.To4()
	if ip4 != nil {
		return ie.NewOuterHeaderCreation(pfcp.OuterHeaderCreation_GTPUUDPIPV4, cfg.TEIDSGWs5u, ip4.String(), "", 0, 0, 0)
	}

	return ie.NewOuterHeaderCreation(pfcp.OuterHeaderCreation_GTPUUDPIPV6, cfg.TEIDSGWs5u, "", cfg.SGWIP.String(), 0, 0, 0)
}

func (cfg SessionConfig) coreOuterHeaderCreation() *ie.IE {
	ip4 := cfg.PGWIP.To4()
	if ip4 != nil {
		return ie.NewOuterHeaderCreation(pfcp.OuterHeaderCreation_GTPUUDPIPV4, cfg.TEIDPGWs5u, ip4.String(), "", 0, 0, 0)
	}

	return ie.NewOuterHeaderCreation(pfcp.OuterHeaderCreation_GTPUUDPIPV6, cfg.TEIDPGWs5u, "", cfg.PGWIP.String(), 0, 0, 0)
}

func (cfg SessionConfig) outerHeaderRemoval() *ie.IE {
	if cfg.PGWIP.To4() != nil {
		return ie.NewOuterHeaderRemoval(pfcp.OuterHeaderRemoval_GTPUUDPIPV4, 0)
	}

	return ie.NewOuterHeaderRemoval(pfcp.OuterHeaderRemoval_GTPUUDPIPV6, 0)
}

func (cfg SessionConfig) forwardFAR(farID uint32) *ie.IE {
	var fwParams []*ie.IE
	switch cfg.Mode {
	case UPGModeTDF, UPGModePGW:
		fwParams = []*ie.IE{
			ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
			ie.NewNetworkInstance(EncodeAPN("sgi")),
		}
	case UPGModeGTPProxy:
		fwParams = []*ie.IE{
			ie.NewDestinationInterface(ie.DstInterfaceCore),
			ie.NewNetworkInstance(EncodeAPN("core")),
			cfg.coreOuterHeaderCreation(),
		}
	}
	if cfg.Redirect {
		fwParams = append(fwParams,
			ie.NewRedirectInformation(ie.RedirectAddrURL, "http://127.0.0.1/this-is-my-redirect/"))
	}
	return ie.NewCreateFAR(
		ie.NewFARID(farID),
		ie.NewApplyAction(pfcp.ApplyAction_FORW),
		ie.NewForwardingParameters(fwParams...))
}

func (cfg SessionConfig) reverseFAR(farID uint32) *ie.IE {
	var fwParams []*ie.IE
	switch cfg.Mode {
	case UPGModeTDF:
		fwParams = []*ie.IE{
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewNetworkInstance(EncodeAPN("access")),
		}
	case UPGModePGW:
		fwParams = []*ie.IE{
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewNetworkInstance(EncodeAPN("epc")),
			cfg.sgwOuterHeaderCreation(),
		}
	case UPGModeGTPProxy:
		fwParams = []*ie.IE{
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewNetworkInstance(EncodeAPN("access")),
			cfg.sgwOuterHeaderCreation(),
		}
	default:
		panic("bad UPGMode")
	}

	return ie.NewCreateFAR(
		ie.NewFARID(farID),
		ie.NewApplyAction(pfcp.ApplyAction_FORW),
		ie.NewForwardingParameters(fwParams...))
}

func (cfg SessionConfig) ueIPAddress(flags uint8) *ie.IE {
	ip4 := cfg.UEIP.To4()
	if ip4 != nil {
		return ie.NewUEIPAddress(flags|pfcp.UEIPAddress_V4, ip4.String(), "", 0)
	}

	return ie.NewUEIPAddress(flags|pfcp.UEIPAddress_V6, "", cfg.UEIP.String(), 0)
}

func (cfg SessionConfig) forwardPDR(pdrID uint16, farID, urrID, precedence uint32, appID string) *ie.IE {
	ies := []*ie.IE{
		ie.NewPDRID(pdrID),
		ie.NewFARID(farID),
		ie.NewPrecedence(precedence),
	}

	var pdiIEs []*ie.IE

	if appID != "" {
		pdiIEs = append(pdiIEs, ie.NewApplicationID(appID))
	}

	switch cfg.Mode {
	case UPGModeTDF:
		pdiIEs = append(pdiIEs,
			ie.NewNetworkInstance(EncodeAPN("access")),
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			cfg.ueIPAddress(0))
	case UPGModePGW:
		ies = append(ies, cfg.outerHeaderRemoval())
		pdiIEs = append(pdiIEs,
			fteid(cfg.TEIDPGWs5u, cfg.PGWIP),
			ie.NewNetworkInstance(EncodeAPN("epc")),
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			cfg.ueIPAddress(0))
	case UPGModeGTPProxy:
		ies = append(ies, cfg.outerHeaderRemoval())
		pdiIEs = append(pdiIEs,
			fteid(cfg.ProxyAccessTEID, cfg.ProxyAccessIP),
			ie.NewNetworkInstance(EncodeAPN("access")),
			ie.NewSourceInterface(ie.SrcInterfaceAccess))
	default:
		panic("bad UPGMode")
	}

	if appID == "" {
		pdiIEs = append(pdiIEs,
			ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0))
	}
	ies = append(ies, ie.NewPDI(pdiIEs...))
	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) reversePDR(pdrID uint16, farID, urrID, precedence uint32, appID string) *ie.IE {
	ies := []*ie.IE{
		ie.NewPDRID(pdrID),
		ie.NewFARID(farID),
		ie.NewPrecedence(precedence),
	}

	var pdiIEs []*ie.IE

	if appID != "" {
		pdiIEs = append(pdiIEs, ie.NewApplicationID(appID))
	}

	switch cfg.Mode {
	case UPGModeTDF, UPGModePGW:
		pdiIEs = append(pdiIEs,
			ie.NewNetworkInstance(EncodeAPN("sgi")),
			ie.NewSourceInterface(ie.SrcInterfaceSGiLANN6LAN),
			cfg.ueIPAddress(pfcp.UEIPAddress_SD))
	case UPGModeGTPProxy:
		ies = append(ies, cfg.outerHeaderRemoval())
		pdiIEs = append(pdiIEs,
			fteid(cfg.ProxyCoreTEID, cfg.ProxyCoreIP),
			ie.NewNetworkInstance(EncodeAPN("core")),
			ie.NewSourceInterface(ie.SrcInterfaceCore))
	}

	if appID == "" {
		pdiIEs = append(pdiIEs,
			ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0))
	}
	ies = append(ies, ie.NewPDI(pdiIEs...))
	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) SessionIEs() []*ie.IE {
	ies := []*ie.IE{
		cfg.forwardFAR(1),
		cfg.reverseFAR(2),
	}
	if !cfg.NoURRs {
		ies = append(ies,
			ie.NewCreateURR(
				ie.NewURRID(1),
				ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
				ie.NewReportingTriggers(0)),
			ie.NewCreateURR(
				ie.NewURRID(2),
				ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
				ie.NewReportingTriggers(0)))
	}

	return append(ies, cfg.CreatePDRs()...)
}

func (cfg SessionConfig) CreatePDRs() []*ie.IE {
	defaultURRId := uint32(1)
	appURRId := uint32(2)
	if cfg.NoURRs {
		defaultURRId = 0
		appURRId = 0
	}
	ies := []*ie.IE{
		cfg.forwardPDR(cfg.IdBase, 1, defaultURRId, 200, ""),
		cfg.reversePDR(cfg.IdBase+1, 2, defaultURRId, 200, ""),
	}
	if cfg.AppName != "" {
		ies = append(ies,
			cfg.forwardPDR(cfg.IdBase+2, 1, appURRId, 100, cfg.AppName),
			cfg.reversePDR(cfg.IdBase+3, 2, appURRId, 100, cfg.AppName))
	}
	return ies
}

func (cfg SessionConfig) DeletePDRs() []*ie.IE {
	ies := []*ie.IE{
		ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase)),
		ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase + 1)),
	}
	if cfg.AppName != "" {
		ies = append(ies,
			ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase+2)),
			ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase+3)))
	}
	return ies
}

func fteid(teid uint32, ip net.IP) *ie.IE {
	ip4 := ip.To4()
	if ip4 != nil {
		return ie.NewFTEID(teid, ip4, nil, nil)
	}

	return ie.NewFTEID(teid, nil, ip, nil) // IPv6
}
