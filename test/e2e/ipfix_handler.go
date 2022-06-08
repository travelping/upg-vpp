// ipfix_handler.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package exttest

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"

	"github.com/travelping/upg-vpp/test/e2e/framework"
)

type ipfixRecord map[string]interface{}

type ipfixHandler struct {
	sync.Mutex
	recs          []ipfixRecord
	stopCh        chan struct{}
	ids           map[uint16]bool
	firstReportTS time.Time
}

func (h *ipfixHandler) handleIPFIXMessage(msg *entities.Message) {
	h.Lock()
	defer h.Unlock()
	var buf bytes.Buffer
	fmt.Fprint(&buf, "\nIPFIX-HDR:\n")
	fmt.Fprintf(&buf, "  version: %v,  Message Length: %v\n", msg.GetVersion(), msg.GetMessageLen())
	fmt.Fprintf(&buf, "  Exported Time: %v (%v)\n", msg.GetExportTime(), time.Unix(int64(msg.GetExportTime()), 0))
	fmt.Fprintf(&buf, "  Sequence No.: %v,  Observation Domain ID: %v\n", msg.GetSequenceNum(), msg.GetObsDomainID())

	set := msg.GetSet()
	if set.GetSetType() == entities.Template {
		fmt.Fprint(&buf, "TEMPLATE SET:\n")
		for i, record := range set.GetRecords() {
			id := record.GetTemplateID()
			if h.ids == nil {
				h.ids = make(map[uint16]bool)
			}
			h.ids[id] = true
			fmt.Fprintf(&buf, "  TEMPLATE RECORD-%d (id %d):\n", i, id)
			for _, ie := range record.GetOrderedElementList() {
				elem := ie.GetInfoElement()
				fmt.Fprintf(&buf, "    %s: len=%d (enterprise ID = %d) \n", elem.Name, elem.Len, elem.EnterpriseId)
			}
		}
	} else {
		now := time.Now()
		if h.firstReportTS.IsZero() {
			h.firstReportTS = now
		}
		fmt.Fprint(&buf, "DATA SET:\n")
		for i, record := range set.GetRecords() {
			fmt.Fprintf(&buf, "  DATA RECORD-%d:\n", i)
			r := map[string]interface{}{
				"observationDomainId": msg.GetObsDomainID(),
				"ts":                  now,
			}
			for _, ie := range record.GetOrderedElementList() {
				elem := ie.GetInfoElement()
				var v interface{}
				switch elem.DataType {
				case entities.Unsigned8:
					v = ie.GetUnsigned8Value()
				case entities.Unsigned16:
					v = ie.GetUnsigned16Value()
				case entities.Unsigned32:
					v = ie.GetUnsigned32Value()
				case entities.Unsigned64:
					v = ie.GetUnsigned64Value()
				case entities.Signed8:
					v = ie.GetSigned8Value()
				case entities.Signed16:
					v = ie.GetSigned16Value()
				case entities.Signed32:
					v = ie.GetSigned32Value()
				case entities.Signed64:
					v = ie.GetSigned64Value()
				case entities.Float32:
					v = ie.GetFloat32Value()
				case entities.Float64:
					v = ie.GetFloat64Value()
				case entities.Boolean:
					v = ie.GetBooleanValue()
				case entities.DateTimeSeconds, entities.DateTimeMilliseconds, entities.DateTimeMicroseconds, entities.DateTimeNanoseconds:
					v = ie.GetDateTimeValue()
				case entities.MacAddress:
					v = ie.GetMacAddressValue()
				case entities.Ipv4Address, entities.Ipv6Address:
					v = ie.GetIPAddressValue()
				case entities.String:
					v = ie.GetStringValue()
				default:
					err := fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
					fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, err)
					continue
				}
				r[elem.Name] = v
				fmt.Fprintf(&buf, "    %s: %v \n", elem.Name, v)
			}
			h.recs = append(h.recs, r)
		}
	}
	framework.Logf("IPFIX:\n%s", buf.String())
}

func (h *ipfixHandler) getTemplateIDs() []int {
	h.Lock()
	defer h.Unlock()

	if len(h.ids) == 0 {
		return nil
	}

	r := make([]int, 0, len(h.ids))
	for id := range h.ids {
		r = append(r, int(id))
	}
	sort.Ints(r)

	return r
}

func (h *ipfixHandler) stop() {
	if h.stopCh != nil {
		close(h.stopCh)
		h.stopCh = nil
	}
}

func (h *ipfixHandler) getRecords() []ipfixRecord {
	h.Lock()
	defer h.Unlock()
	return h.recs
}

func (h *ipfixHandler) getFirstReportTS() time.Time {
	h.Lock()
	defer h.Unlock()
	return h.firstReportTS
}

func setupIPFIX(f *framework.Framework, listenIP net.IP) *ipfixHandler {
	// Load the IPFIX global registry
	registry.LoadRegistry()
	// Initialize collecting process
	if listenIP == nil {
		listenIP = f.PFCPCfg.CNodeIP
	}
	cpInput := collector.CollectorInput{
		Address:       fmt.Sprintf("%s:%d", listenIP, IPFIX_PORT),
		Protocol:      "udp",
		MaxBufferSize: 65535,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := collector.InitCollectingProcess(cpInput)
	framework.ExpectNoError(err, "IPFIX collector init")
	go func() {
		f.VPP.GetNS("cp").Do(func() error {
			cp.Start()
			return nil
		})
	}()
	msgCh := cp.GetMsgChan()
	handler := &ipfixHandler{stopCh: make(chan struct{})}
	go func() {
		for {
			select {
			case <-handler.stopCh:
				cp.Stop()
				return
			case msg := <-msgCh:
				handler.handleIPFIXMessage(msg)
			}
		}
	}()
	return handler
}
