package framework

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
)

type SessionConfig struct {
	IdBase uint16
	UEIP   net.IP
	AppPDR bool
}

func (cfg SessionConfig) SessionIEs() []*ie.IE {
	ies := []*ie.IE{
		ie.NewCreateFAR(
			ie.NewApplyAction(ApplyAction_FORW),
			ie.NewFARID(1),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
				ie.NewNetworkInstance(EncodeAPN("sgi")))),
		// TODO: replace for PGW (reverseFAR)
		ie.NewCreateFAR(
			ie.NewApplyAction(ApplyAction_FORW),
			ie.NewFARID(2),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewNetworkInstance(EncodeAPN("access")))),
		ie.NewCreateURR(
			ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
			ie.NewReportingTriggers(0),
			ie.NewURRID(1)),
		ie.NewCreateURR(
			ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
			ie.NewReportingTriggers(0),
			ie.NewURRID(2)),
	}

	return append(ies, cfg.CreatePDRs()...)
}

func (cfg SessionConfig) CreatePDRs() []*ie.IE {
	ies := []*ie.IE{
		// TODO: replace for PGW (forwardPDR)
		ie.NewCreatePDR(
			ie.NewFARID(1),
			ie.NewPDI(
				ie.NewNetworkInstance(EncodeAPN("access")),
				ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0),
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				// TODO: replace for IPv6
				ie.NewUEIPAddress(UEIPAddress_V4, cfg.UEIP.String(), "", 0)),
			ie.NewPDRID(cfg.IdBase),
			ie.NewPrecedence(200),
			ie.NewURRID(1),
		),
		ie.NewCreatePDR(
			ie.NewFARID(2),
			ie.NewPDI(
				ie.NewNetworkInstance(EncodeAPN("sgi")),
				ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0),
				ie.NewSourceInterface(ie.SrcInterfaceSGiLANN6LAN),
				// TODO: replace for IPv6
				ie.NewUEIPAddress(UEIPAddress_V4|UEIPAddress_SD, cfg.UEIP.String(), "", 0)),
			ie.NewPDRID(cfg.IdBase+1),
			ie.NewPrecedence(200),
			ie.NewURRID(1),
		),
	}
	if cfg.AppPDR {
		ies = append(ies,
			ie.NewCreatePDR(
				ie.NewFARID(1),
				ie.NewPDI(
					ie.NewApplicationID("TST"),
					ie.NewNetworkInstance(EncodeAPN("access")),
					ie.NewSourceInterface(ie.SrcInterfaceAccess),
					// TODO: replace for IPv6
					ie.NewUEIPAddress(UEIPAddress_V4, cfg.UEIP.String(), "", 0)),
				ie.NewPDRID(cfg.IdBase+2),
				ie.NewPrecedence(100),
				ie.NewURRID(2)),
			ie.NewCreatePDR(
				ie.NewFARID(2),
				ie.NewPDI(
					ie.NewApplicationID("TST"),
					ie.NewNetworkInstance(EncodeAPN("sgi")),
					ie.NewSourceInterface(ie.SrcInterfaceSGiLANN6LAN),
					// TODO: replace for IPv6
					ie.NewUEIPAddress(UEIPAddress_V4|UEIPAddress_SD, cfg.UEIP.String(), "", 0)),
				ie.NewPDRID(cfg.IdBase+3),
				ie.NewPrecedence(100),
				ie.NewURRID(2)))
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
