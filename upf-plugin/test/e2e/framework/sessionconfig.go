// sessionconfig.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"net"
	"time"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/travelping/upg-vpp/test/e2e/pfcp"
)

type SessionConfig struct {
	PDRIdBase          uint16
	FARIdBase          uint32
	URRIdBase          uint32
	QERIdBase          uint32
	UEIP               net.IP
	PGWIP              net.IP
	SGWIP              net.IP
	AppName            string
	Redirect           bool
	NoADFSDFFilter     string
	Mode               UPGMode
	TEIDPGWs5u         uint32
	TEIDSGWs5u         uint32
	ProxyAccessIP      net.IP
	ProxyCoreIP        net.IP
	ProxyAccessTEID    uint32
	ProxyCoreTEID      uint32
	NoURRs             bool
	HasQERs            bool
	MonitoringTime     time.Time
	VTime              time.Duration
	MeasurementPeriod  time.Duration
	VolumeQuota        uint32
	ForwardingPolicyID string
	NatPoolName        string
	IMSI               string
	IPFIXTemplate      string
	SkipSDFFilter      bool
	URRStartEv         bool
	FARSendEndMarker   bool
	TunnelServerIP     net.IP
}

const (
	HTTPAppName = "TST"
	IPAppName   = "IPAPP"
)

func (cfg SessionConfig) SgwOuterHeaderCreation() *ie.IE {
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

// From IANA Private Enterprise Numbers Registry, Broadband Forum Enterprise ID is 3561 (0x0DE9)
// Enterprise Specific IE Types are marked with 0x8000 mask
const (
	BBF_EID                 = 3561
	TP_EID                  = 18681
	ETYPE_MASK              = 0x8000
	BBF_TYPE_APPLY_ACTION   = 15
	BBF_TYPE_NAT_PORT_BLOCK = 18
	BBF_APPLY_ACTION_NAT    = 1
	TP_IPFIX_TEMPLATE       = 11
)

func newVendorSpecificStringIE(itype uint16, eid uint16, data string) *ie.IE {
	return ie.NewVendorSpecificIE(itype, eid, []byte(data))
}

func newVendorSpecificU8IE(itype uint16, eid uint16, val uint8) *ie.IE {
	return ie.NewVendorSpecificIE(itype, eid, []byte{val})
}

func (cfg SessionConfig) ipfixTemplateIEs() []*ie.IE {
	// IEs should be created for uplink FARs only
	if cfg.IPFIXTemplate == "" {
		return nil
	}

	template := cfg.IPFIXTemplate
	if template == "none" {
		// "none" template is specified as an empty string
		template = ""
	}
	return []*ie.IE{
		newVendorSpecificStringIE(
			ETYPE_MASK|TP_IPFIX_TEMPLATE, TP_EID, cfg.IPFIXTemplate),
	}
}

func (cfg SessionConfig) createOrUpdateForwardFAR(farID uint32, flag uint8, update bool) *ie.IE {
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
		if update && cfg.FARSendEndMarker {
			fwParams = append(fwParams, ie.NewPFCPSMReqFlags(2))
		}
	}
	if cfg.Redirect {
		fwParams = append(fwParams,
			ie.NewRedirectInformation(ie.RedirectAddrURL, "http://127.0.0.1/this-is-my-redirect/"))
	}
	if cfg.ForwardingPolicyID != "" {
		fwParams = append(fwParams, ie.NewForwardingPolicy(cfg.ForwardingPolicyID))
	}
	if cfg.NatPoolName != "" {
		fwParams = append(fwParams, newVendorSpecificU8IE(ETYPE_MASK|BBF_TYPE_APPLY_ACTION, BBF_EID, BBF_APPLY_ACTION_NAT))
		fwParams = append(fwParams, newVendorSpecificStringIE(ETYPE_MASK|BBF_TYPE_NAT_PORT_BLOCK, BBF_EID, cfg.NatPoolName))
	}

	ies := append([]*ie.IE{
		ie.NewFARID(farID),
		ie.NewApplyAction(flag),
	}, cfg.ipfixTemplateIEs()...)

	if update {
		return ie.NewUpdateFAR(append(ies, ie.NewUpdateForwardingParameters(fwParams...))...)
	} else {
		return ie.NewCreateFAR(append(ies, ie.NewForwardingParameters(fwParams...))...)
	}
}

func (cfg SessionConfig) createOrUpdateReverseFAR(farID uint32, flag uint8, update bool) *ie.IE {
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
			cfg.SgwOuterHeaderCreation(),
		}
	case UPGModeGTPProxy:
		fwParams = []*ie.IE{
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewNetworkInstance(EncodeAPN("access")),
			cfg.SgwOuterHeaderCreation(),
		}
	default:
		panic("bad UPGMode")
	}
	if update && cfg.FARSendEndMarker {
		fwParams = append(fwParams, ie.NewPFCPSMReqFlags(2))
	}

	ies := []*ie.IE{
		ie.NewFARID(farID),
		ie.NewApplyAction(flag),
	}
	if update {
		return ie.NewUpdateFAR(append(ies, ie.NewUpdateForwardingParameters(fwParams...))...)
	} else {
		return ie.NewCreateFAR(append(ies, ie.NewForwardingParameters(fwParams...))...)
	}
}

func (cfg SessionConfig) ueIPAddress(flags uint8) *ie.IE {
	ip4 := cfg.UEIP.To4()
	if ip4 != nil {
		return ie.NewUEIPAddress(flags|pfcp.UEIPAddress_V4, ip4.String(), "", 0, 0)
	}

	return ie.NewUEIPAddress(flags|pfcp.UEIPAddress_V6, "", cfg.UEIP.String(), 0, 0)
}

func (cfg SessionConfig) ForwardPDR(pdrID uint16, farID, urrID, qerID, precedence uint32, appID string, sdfFilter string) *ie.IE {
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
		)
		if cfg.UEIP != nil {
			pdiIEs = append(pdiIEs, cfg.ueIPAddress(0))
		}
	case UPGModePGW:
		ies = append(ies, cfg.outerHeaderRemoval())
		pdiIEs = append(pdiIEs,
			fteidProvided(cfg.TEIDPGWs5u, cfg.PGWIP),
			ie.NewNetworkInstance(EncodeAPN("epc")),
			ie.NewSourceInterface(ie.SrcInterfaceAccess))
		if cfg.UEIP != nil {
			pdiIEs = append(pdiIEs, cfg.ueIPAddress(0))
		}
	case UPGModeGTPProxy:
		ies = append(ies, cfg.outerHeaderRemoval())
		if cfg.ProxyAccessTEID != 0 {
			pdiIEs = append(pdiIEs,
				fteidProvided(cfg.ProxyAccessTEID, cfg.ProxyAccessIP),
				ie.NewNetworkInstance(EncodeAPN("access")),
				ie.NewSourceInterface(ie.SrcInterfaceAccess))
		} else {
			pdiIEs = append(pdiIEs,
				fteidChoose(uint8(pdrID), cfg.ProxyAccessIP.To4() != nil),
				ie.NewNetworkInstance(EncodeAPN("access")),
				ie.NewSourceInterface(ie.SrcInterfaceAccess))
		}

	default:
		panic("bad UPGMode")
	}

	if appID == "" && !cfg.SkipSDFFilter {
		if sdfFilter == "" {
			if cfg.UEIP != nil {
				sdfFilter = "permit out ip from any to assigned"
			} else {
				// Proper version:
				// sdfFilter = "permit out ip from any to any"
				// Test against version used by control plane
				sdfFilter = "permit out ip from any to assigned"
			}
		}
		pdiIEs = append(pdiIEs, ie.NewSDFFilter(sdfFilter, "", "", "", 0))
	}

	ies = append(ies, ie.NewPDI(pdiIEs...))
	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}
	if qerID != 0 {
		ies = append(ies, ie.NewQERID(qerID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) ReversePDR(pdrID uint16, farID, urrID, qerID, precedence uint32, appID, sdfFilter string) *ie.IE {
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
			ie.NewSourceInterface(ie.SrcInterfaceSGiLANN6LAN))
		if cfg.UEIP != nil {
			pdiIEs = append(pdiIEs, cfg.ueIPAddress(pfcp.UEIPAddress_SD))
		}

	case UPGModeGTPProxy:
		ies = append(ies, cfg.outerHeaderRemoval())
		if cfg.ProxyCoreTEID != 0 {
			pdiIEs = append(pdiIEs,
				fteidProvided(cfg.ProxyCoreTEID, cfg.ProxyCoreIP),
				ie.NewNetworkInstance(EncodeAPN("core")),
				ie.NewSourceInterface(ie.SrcInterfaceCore))
		} else {
			pdiIEs = append(pdiIEs,
				fteidChoose(uint8(pdrID), cfg.ProxyCoreIP.To4() != nil),
				ie.NewNetworkInstance(EncodeAPN("core")),
				ie.NewSourceInterface(ie.SrcInterfaceCore))
		}
	}

	if appID == "" && !cfg.SkipSDFFilter {
		if sdfFilter == "" {
			if cfg.UEIP != nil {
				sdfFilter = "permit out ip from any to assigned"
			} else {
				sdfFilter = "permit out ip from any to any"
			}
		}
		pdiIEs = append(pdiIEs,
			ie.NewSDFFilter(sdfFilter, "", "", "", 0))
	}
	ies = append(ies, ie.NewPDI(pdiIEs...))
	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}
	if qerID != 0 {
		ies = append(ies, ie.NewQERID(qerID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) CreateFARs(flag uint8) []*ie.IE {
	return []*ie.IE{
		cfg.createOrUpdateForwardFAR(cfg.FARIdBase+1, flag, false),
		cfg.createOrUpdateReverseFAR(cfg.FARIdBase+2, flag, false),
	}
}

func (cfg SessionConfig) DeleteFARs() []*ie.IE {
	return []*ie.IE{
		ie.NewRemoveFAR(ie.NewFARID(cfg.FARIdBase + 1)),
		ie.NewRemoveFAR(ie.NewFARID(cfg.FARIdBase + 2)),
	}
}

func (cfg SessionConfig) UpdateFARs(flag uint8) []*ie.IE {
	return []*ie.IE{
		cfg.createOrUpdateForwardFAR(cfg.FARIdBase+1, flag, true),
		cfg.createOrUpdateReverseFAR(cfg.FARIdBase+2, flag, true),
	}
}

func (cfg SessionConfig) createOrUpdateURR(id uint32, update bool) *ie.IE {
	triggers := [2]byte{}
	methodVOLUM := 1
	methodDURAT := 1
	methodEVENT := 0

	mk := ie.NewCreateURR
	if update {
		mk = ie.NewUpdateURR
	}
	if cfg.VTime != 0 {
		methodDURAT = 0
	}
	if cfg.URRStartEv {
		methodEVENT = 1
		// can't be combined by spec
		methodDURAT = 0
		methodVOLUM = 0
	}
	urr := mk(ie.NewURRID(id),
		ie.NewMeasurementMethod(methodEVENT, methodVOLUM, methodDURAT))
	if !cfg.MonitoringTime.IsZero() {
		urr.Add(ie.NewMonitoringTime(cfg.MonitoringTime))
	}
	if cfg.VTime != 0 {
		urr.Add(ie.NewQuotaValidityTime(cfg.VTime))
		triggers[1] |= pfcp.ReportingTriggers1_QUVTI
	}
	if cfg.MeasurementPeriod != 0 {
		urr.Add(ie.NewMeasurementPeriod(cfg.MeasurementPeriod))
		triggers[0] |= pfcp.ReportingTriggers0_PERIO
	}
	if cfg.URRStartEv {
		triggers[0] |= pfcp.ReportingTriggers0_START
	}
	urr.Add(ie.NewReportingTriggers(triggers[:]...))
	return urr
}

func (cfg SessionConfig) CreateVolumeURR(id, tvol uint32) *ie.IE {
	var triggers [2]byte
	triggers[1] |= pfcp.ReportingTriggers1_VOLQU
	urr := ie.NewCreateURR(
		ie.NewURRID(id),
		ie.NewMeasurementMethod(0, 1, 1),
		ie.NewVolumeQuota(0x01, uint64(tvol), 0, 0),
		ie.NewReportingTriggers(triggers[:]...))
	return urr
}

func (cfg SessionConfig) QueryURR(id uint32) *ie.IE {
	return ie.NewQueryURR(ie.NewURRID(id))
}

func (cfg SessionConfig) DeleteURR(id uint32) *ie.IE {
	return ie.NewRemoveURR(ie.NewURRID(id))
}

func (cfg SessionConfig) CreateURRs() []*ie.IE {
	if cfg.VolumeQuota != 0 {
		return []*ie.IE{
			cfg.CreateVolumeURR(cfg.URRIdBase+1, cfg.VolumeQuota),
			cfg.CreateVolumeURR(cfg.URRIdBase+2, cfg.VolumeQuota),
		}
	}
	return []*ie.IE{
		cfg.createOrUpdateURR(cfg.URRIdBase+1, false),
		cfg.createOrUpdateURR(cfg.URRIdBase+2, false),
	}
}

func (cfg SessionConfig) UpdateURRs() []*ie.IE {
	return []*ie.IE{
		cfg.createOrUpdateURR(cfg.URRIdBase+1, true),
		cfg.createOrUpdateURR(cfg.URRIdBase+2, true),
	}
}

func (cfg SessionConfig) DeleteURRs() []*ie.IE {
	return []*ie.IE{
		cfg.DeleteURR(cfg.URRIdBase + 1),
		cfg.DeleteURR(cfg.URRIdBase + 2),
	}
}

func (cfg SessionConfig) QueryURRs() []*ie.IE {
	return []*ie.IE{
		cfg.QueryURR(cfg.URRIdBase + 1),
		cfg.QueryURR(cfg.URRIdBase + 2),
	}
}

func (cfg SessionConfig) CreateQER(gateOpen bool, mbr uint64) []*ie.IE {
	s := ie.GateStatusClosed
	if gateOpen {
		s = ie.GateStatusOpen
	}
	ies := []*ie.IE{
		ie.NewQERID(cfg.QERIdBase + 1),
		ie.NewGateStatus(s, s),
	}
	if mbr != 0 {
		ies = append(ies, ie.NewMBR(mbr, mbr))
	}
	return []*ie.IE{
		ie.NewCreateQER(ies...),
	}
}

func (cfg SessionConfig) SessionIEs() []*ie.IE {
	ies := cfg.CreateFARs(pfcp.ApplyAction_FORW)
	if !cfg.NoURRs {
		ies = append(ies, cfg.CreateURRs()...)
	}

	ies = append(ies, cfg.CreatePDRs()...)
	if cfg.IMSI != "" {
		// flags == 1: IMSIF bit set
		ies = append(ies, ie.NewUserID(1, cfg.IMSI, "", "", ""))
	}

	return ies
}

func (cfg SessionConfig) CreatePDRs() []*ie.IE {
	defaultURRId := cfg.URRIdBase + 1
	appURRId := cfg.URRIdBase + 2
	defaultQERId := cfg.QERIdBase + 1
	if cfg.NoURRs {
		defaultURRId = 0
		appURRId = 0
	}
	if !cfg.HasQERs {
		defaultQERId = 0
	}
	ies := []*ie.IE{
		cfg.ForwardPDR(cfg.PDRIdBase+1, cfg.FARIdBase+1, defaultURRId, defaultQERId, 200, "", ""),
		cfg.ReversePDR(cfg.PDRIdBase+2, cfg.FARIdBase+2, defaultURRId, defaultQERId, 200, "", ""),
	}
	if cfg.AppName != "" {
		ies = append(ies,
			cfg.ForwardPDR(cfg.PDRIdBase+3, cfg.FARIdBase+1, appURRId, defaultQERId, 100, cfg.AppName, ""),
			cfg.ReversePDR(cfg.PDRIdBase+4, cfg.FARIdBase+2, appURRId, defaultQERId, 100, cfg.AppName, ""))
		if cfg.NoADFSDFFilter != "" {
			ies = append(ies,
				cfg.ForwardPDR(cfg.PDRIdBase+5, cfg.FARIdBase+1, defaultQERId, 0, 10, "", cfg.NoADFSDFFilter),
				cfg.ReversePDR(cfg.PDRIdBase+6, cfg.FARIdBase+2, defaultQERId, 0, 10, "", cfg.NoADFSDFFilter))
		}
	}
	return ies
}

func (cfg SessionConfig) DeletePDRs() []*ie.IE {
	ies := []*ie.IE{
		ie.NewRemovePDR(ie.NewPDRID(cfg.PDRIdBase + 1)),
		ie.NewRemovePDR(ie.NewPDRID(cfg.PDRIdBase + 2)),
	}
	if cfg.AppName != "" {
		ies = append(ies,
			ie.NewRemovePDR(ie.NewPDRID(cfg.PDRIdBase+3)),
			ie.NewRemovePDR(ie.NewPDRID(cfg.PDRIdBase+4)))
	}
	return ies
}

func fteidProvided(teid uint32, ip net.IP) *ie.IE {
	ip4 := ip.To4()
	var flags uint8
	if ip4 != nil {
		flags |= 0x01
		return ie.NewFTEID(flags, teid, ip4, nil, 0)
	}

	flags |= 0x02
	return ie.NewFTEID(flags, teid, nil, ip, 0) // IPv6
}

func fteidChoose(chid uint8, ipv4 bool) *ie.IE {
	var flags uint8

	if ipv4 {
		flags |= 0x01 // ipv4 bit
	} else {
		flags |= 0x02 // ipv6 bit
	}

	flags |= 0xc // chid, ch
	return ie.NewFTEID(flags, 0, nil, nil, chid)
}
