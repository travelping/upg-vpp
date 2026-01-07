// ns_unsupported.go - 3GPP TS 29.244 GTP-U UP plug-in
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

// +build !linux

package ns

import (
	"errors"
)

var notImplemented = errors.New("not implemented")

func getCurrentThreadNetNSPath() string {
	panic(notImplemented)
}

func (ns *netNS) Set() error {
	return notImplemented
}

// Creates a new persistent (bind-mounted) network namespace and returns an object
// representing that namespace, without switching to it.
func NewNS(name string) (NetNS, error) {
	return nil, notImplemented
}
