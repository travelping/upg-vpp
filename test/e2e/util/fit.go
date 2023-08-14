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

type FITHook struct {
	faultEnabled map[string]bool
}

const (
	// Faults
	FaultSessionForgot = "session_forgot"
)

func (h *FITHook) IsFaultInjected(name string) bool {
	return h.faultEnabled[name]
}

func (h *FITHook) EnableFault(name string) {
	if h.faultEnabled == nil {
		h.faultEnabled = make(map[string]bool)
	}
	h.faultEnabled[name] = true
}
