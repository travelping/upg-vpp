package framework

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
)

type SessionConfig struct {
	IdBase     uint16
	UEIP       net.IP
	PGWGRXIP   net.IP
	SGWGRXIP   net.IP
	AppPDR     bool
	Redirect   bool
	Mode       UPGMode
	TEIDPGWs5u uint32
	TEIDSGWs5u uint32
}

func (cfg SessionConfig) outerHeaderCreation() *ie.IE {
	ip4 := cfg.SGWGRXIP.To4()
	if ip4 != nil {
		return ie.NewOuterHeaderCreation(OuterHeaderCreation_GTPUUDPIPV4, cfg.TEIDSGWs5u, ip4.String(), "", 0, 0, 0)
	}

	return ie.NewOuterHeaderCreation(OuterHeaderCreation_GTPUUDPIPV6, cfg.TEIDSGWs5u, "", cfg.SGWGRXIP.String(), 0, 0, 0)
}

func (cfg SessionConfig) outerHeaderRemoval() *ie.IE {
	if cfg.PGWGRXIP.To4() != nil {
		return ie.NewOuterHeaderRemoval(OuterHeaderRemoval_GTPUUDPIPV4, 0)
	}

	return ie.NewOuterHeaderRemoval(OuterHeaderRemoval_GTPUUDPIPV6, 0)
}

func (cfg SessionConfig) ieFTEID() *ie.IE {
	ip4 := cfg.PGWGRXIP.To4()
	if ip4 != nil {
		return ie.NewFTEID(cfg.TEIDPGWs5u, ip4, nil, nil)
	}

	return ie.NewFTEID(cfg.TEIDPGWs5u, nil, cfg.PGWGRXIP, nil)
}

func (cfg SessionConfig) forwardFAR(farID uint32) *ie.IE {
	fwParams := []*ie.IE{
		ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
		ie.NewNetworkInstance(EncodeAPN("sgi")),
	}
	if cfg.Redirect {
		fwParams = append(fwParams,
			ie.NewRedirectInformation(ie.RedirectAddrURL, "http://127.0.0.1/this-is-my-redirect/"))
	}
	return ie.NewCreateFAR(
		ie.NewFARID(farID),
		ie.NewApplyAction(ApplyAction_FORW),
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
			cfg.outerHeaderCreation(),
		}
	default:
		panic("bad UPGMode")
	}

	return ie.NewCreateFAR(
		ie.NewFARID(farID),
		ie.NewApplyAction(ApplyAction_FORW),
		ie.NewForwardingParameters(fwParams...))
}

func (cfg SessionConfig) ueIPAddress(flags uint8) *ie.IE {
	ip4 := cfg.UEIP.To4()
	if ip4 != nil {
		return ie.NewUEIPAddress(flags|UEIPAddress_V4, ip4.String(), "", 0)
	}

	return ie.NewUEIPAddress(flags|UEIPAddress_V6, "", cfg.UEIP.String(), 0)
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
			ie.NewNetworkInstance(EncodeAPN("access")))
	case UPGModePGW:
		ies = append(ies, cfg.outerHeaderRemoval())
		pdiIEs = append(pdiIEs,
			cfg.ieFTEID(),
			ie.NewNetworkInstance(EncodeAPN("epc")))
	default:
		panic("bad UPGMode")
	}

	if appID == "" {
		pdiIEs = append(pdiIEs,
			ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0))
	}
	pdiIEs = append(pdiIEs,
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
		cfg.ueIPAddress(0))
	ies = append(ies, ie.NewPDI(pdiIEs...))
	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) reversePDR(pdrID uint16, farID, urrID, precedence uint32, appID string) *ie.IE {
	var pdiIEs []*ie.IE

	if appID != "" {
		pdiIEs = append(pdiIEs, ie.NewApplicationID(appID))
	} else {
		pdiIEs = append(pdiIEs, ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0))
	}

	pdiIEs = append(pdiIEs,
		ie.NewNetworkInstance(EncodeAPN("sgi")),
		ie.NewSourceInterface(ie.SrcInterfaceSGiLANN6LAN),
		cfg.ueIPAddress(UEIPAddress_SD))

	ies := []*ie.IE{
		ie.NewPDRID(pdrID),
		ie.NewFARID(farID),
		ie.NewPDI(pdiIEs...),
		ie.NewPrecedence(precedence),
	}

	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) SessionIEs() []*ie.IE {
	ies := []*ie.IE{
		cfg.forwardFAR(1),
		cfg.reverseFAR(2),
		ie.NewCreateURR(
			ie.NewURRID(1),
			ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
			ie.NewReportingTriggers(0)),
		ie.NewCreateURR(
			ie.NewURRID(2),
			ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
			ie.NewReportingTriggers(0)),
	}

	return append(ies, cfg.CreatePDRs()...)
}

func (cfg SessionConfig) CreatePDRs() []*ie.IE {
	ies := []*ie.IE{
		cfg.forwardPDR(cfg.IdBase, 1, 1, 200, ""),
		cfg.reversePDR(cfg.IdBase+1, 2, 1, 200, ""),
	}
	if cfg.AppPDR {
		ies = append(ies,
			cfg.forwardPDR(cfg.IdBase+2, 1, 2, 100, "TST"),
			cfg.reversePDR(cfg.IdBase+3, 2, 2, 100, "TST"))
	}
	return ies
}

func (cfg SessionConfig) DeletePDRs() []*ie.IE {
	ies := []*ie.IE{
		ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase)),
		ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase + 1)),
	}
	if cfg.AppPDR {
		ies = append(ies,
			ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase+2)),
			ie.NewRemovePDR(ie.NewPDRID(cfg.IdBase+3)))
	}
	return ies
}
