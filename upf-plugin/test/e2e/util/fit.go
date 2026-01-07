// framework.go - 3GPP TS 29.244 GTP-U UP plug-in
//
// Copyright (c) 2023 Travelping GmbH
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

package util

type FaultType = string

type FITHook struct {
	faultEnabled map[FaultType]bool
}

const (
	FaultSessionForgot    FaultType = "session_forgot"
	FaultNoReportResponse FaultType = "no_report_response"

	// IgnoreHeartbeatRequests makes PFCPConnection ignore incoming
	// PFCP Heartbeat Requests, thus simulating a faulty CP.
	FaultIgnoreHeartbeat FaultType = "ignore_heartbeat"
)

func (h *FITHook) IsFaultInjected(name FaultType) bool {
	if h == nil {
		return false
	}
	return h.faultEnabled[name]
}

func (h *FITHook) EnableFault(name FaultType) {
	if h.faultEnabled == nil {
		h.faultEnabled = make(map[FaultType]bool)
	}
	h.faultEnabled[name] = true
}
