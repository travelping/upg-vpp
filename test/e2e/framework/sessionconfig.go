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
	"encoding/binary"
	"math"
	"net"
	"time"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/travelping/upg-vpp/test/e2e/pfcp"
)

type SessionConfig struct {
	IdBase             uint16
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
	MonitoringTime     time.Time
	VTime              time.Duration
	MeasurementPeriod  time.Duration
	VolumeQuota        uint32
	ForwardingPolicyID string
	NatPoolName        string
	IMSI               string
	IPFIXTemplate      string
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
	if cfg.ForwardingPolicyID != "" {
		fwParams = append(fwParams, ie.NewForwardingPolicy(cfg.ForwardingPolicyID))
	}
	if cfg.NatPoolName != "" {
		fwParams = append(fwParams, newVendorSpecificU8IE(ETYPE_MASK|BBF_TYPE_APPLY_ACTION, BBF_EID, BBF_APPLY_ACTION_NAT))
		fwParams = append(fwParams, newVendorSpecificStringIE(ETYPE_MASK|BBF_TYPE_NAT_PORT_BLOCK, BBF_EID, cfg.NatPoolName))
	}

	ies := append([]*ie.IE{
		ie.NewFARID(farID),
		ie.NewApplyAction(pfcp.ApplyAction_FORW),
		ie.NewForwardingParameters(fwParams...),
	}, cfg.ipfixTemplateIEs()...)
	return ie.NewCreateFAR(ies...)
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

	ies := append([]*ie.IE{
		ie.NewFARID(farID),
		ie.NewApplyAction(pfcp.ApplyAction_FORW),
		ie.NewForwardingParameters(fwParams...),
	}, cfg.ipfixTemplateIEs()...)
	return ie.NewCreateFAR(ies...)
}

func (cfg SessionConfig) ueIPAddress(flags uint8) *ie.IE {
	ip4 := cfg.UEIP.To4()
	if ip4 != nil {
		return ie.NewUEIPAddress(flags|pfcp.UEIPAddress_V4, ip4.String(), "", 0, 0)
	}

	return ie.NewUEIPAddress(flags|pfcp.UEIPAddress_V6, "", cfg.UEIP.String(), 0, 0)
}

func (cfg SessionConfig) forwardPDR(pdrID uint16, farID, urrID, precedence uint32, appID string, sdfFilter string) *ie.IE {
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
		if sdfFilter == "" {
			sdfFilter = "permit out ip from any to assigned"
		}
		pdiIEs = append(pdiIEs, ie.NewSDFFilter(sdfFilter, "", "", "", 0))
	}

	ies = append(ies, ie.NewPDI(pdiIEs...))
	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) reversePDR(pdrID uint16, farID, urrID, precedence uint32, appID, sdfFilter string) *ie.IE {
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
		if sdfFilter == "" {
			sdfFilter = "permit out ip from any to assigned"
		}
		pdiIEs = append(pdiIEs,
			ie.NewSDFFilter(sdfFilter, "", "", "", 0))
	}
	ies = append(ies, ie.NewPDI(pdiIEs...))
	if urrID != 0 {
		ies = append(ies, ie.NewURRID(urrID))
	}

	return ie.NewCreatePDR(ies...)
}

func (cfg SessionConfig) CreateFARs() []*ie.IE {
	return []*ie.IE{
		cfg.forwardFAR(1),
		cfg.reverseFAR(2),
	}
}

func (cfg SessionConfig) DeleteFARs() []*ie.IE {
	return []*ie.IE{
		ie.NewRemoveFAR(ie.NewFARID(uint32(cfg.IdBase))),
		ie.NewRemoveFAR(ie.NewFARID(uint32(cfg.IdBase + 1))),
	}
}

func (cfg SessionConfig) CreateOrUpdateURR(id uint32, update bool) *ie.IE {
	triggers := uint16(0)
	measurementMethodDURAT := 1
	mk := ie.NewCreateURR
	if update {
		mk = ie.NewUpdateURR
	}
	if cfg.VTime != 0 {
		measurementMethodDURAT = 0
	}
	urr := mk(ie.NewURRID(id),
		// VOLUM=1 DURAT=1
		ie.NewMeasurementMethod(0, 1, measurementMethodDURAT))
	if !cfg.MonitoringTime.IsZero() {
		urr.Add(ie.NewMonitoringTime(cfg.MonitoringTime))
	}
	if cfg.VTime != 0 {
		// FIXME: go-pfcp QuotaValidityTime definition is incorrect, as it should contain
		// a Duration, not Time
		urr.Add(ie.NewQuotaValidityTime(time.Time{}))
		qvt, _ := urr.FindByType(ie.QuotaValidityTime)
		s := uint32(math.Round(cfg.VTime.Seconds()))
		binary.BigEndian.PutUint32(qvt.Payload, s)
		triggers |= pfcp.ReportingTriggers_QUVTI
	}
	if cfg.MeasurementPeriod != 0 {
		urr.Add(ie.NewMeasurementPeriod(cfg.MeasurementPeriod))
		triggers |= pfcp.ReportingTriggers_PERIO
	}
	urr.Add(ie.NewReportingTriggers(triggers))
	return urr
}

func (cfg SessionConfig) CreateVolumeURR(id uint32) *ie.IE {
	triggers := uint16(0)
	triggers |= pfcp.ReportingTriggers_VOLQU
	urr := ie.NewCreateURR(ie.NewURRID(id),
		ie.NewMeasurementMethod(0, 1, 1),
		ie.NewVolumeQuota(0x01, 1024, 0, 0),
		ie.NewReportingTriggers(triggers))
	return urr
}

func (cfg SessionConfig) DeleteURR(id uint32) *ie.IE {
	return ie.NewRemoveURR(ie.NewURRID(id))
}

func (cfg SessionConfig) CreateURRs() []*ie.IE {
	if cfg.VolumeQuota != 0 {
		return []*ie.IE{cfg.CreateVolumeURR(1), cfg.CreateVolumeURR(2)}
	}
	return []*ie.IE{cfg.CreateOrUpdateURR(1, false), cfg.CreateOrUpdateURR(2, false)}
}

func (cfg SessionConfig) UpdateURRs() []*ie.IE {
	return []*ie.IE{cfg.CreateOrUpdateURR(1, true), cfg.CreateOrUpdateURR(2, true)}
}

func (cfg SessionConfig) DeleteURRs() []*ie.IE {
	return []*ie.IE{cfg.DeleteURR(1), cfg.DeleteURR(2)}
}

func (cfg SessionConfig) SessionIEs() []*ie.IE {
	ies := cfg.CreateFARs()
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
	defaultURRId := uint32(1)
	appURRId := uint32(2)
	if cfg.NoURRs {
		defaultURRId = 0
		appURRId = 0
	}
	ies := []*ie.IE{
		cfg.forwardPDR(cfg.IdBase, 1, defaultURRId, 200, "", ""),
		cfg.reversePDR(cfg.IdBase+1, 2, defaultURRId, 200, "", ""),
	}
	if cfg.AppName != "" {
		ies = append(ies,
			cfg.forwardPDR(cfg.IdBase+2, 1, appURRId, 100, cfg.AppName, ""),
			cfg.reversePDR(cfg.IdBase+3, 2, appURRId, 100, cfg.AppName, ""))
		if cfg.NoADFSDFFilter != "" {
			ies = append(ies,
				cfg.forwardPDR(cfg.IdBase+4, 1, 0, 10, "", cfg.NoADFSDFFilter),
				cfg.reversePDR(cfg.IdBase+5, 2, 0, 10, "", cfg.NoADFSDFFilter))
		}
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
	var flags uint8
	if ip4 != nil {
		flags |= 0x01
		return ie.NewFTEID(flags, teid, ip4, nil, 0)
	}

	flags |= 0x02
	return ie.NewFTEID(flags, teid, nil, ip, 0) // IPv6
}
