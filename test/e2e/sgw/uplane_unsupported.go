// uplane_unsupported.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package sgw

import (
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	RoleSGSN   = 1
	FAMILY_ALL = unix.AF_UNSPEC
	SCOPE_LINK = 0
)

func (kt *KernelTunnel) UnregisterSession(s Session) error {
	return errors.New("not implemented")
}

func (kt *KernelTunnel) addTunnel(s Session) error {
	return errors.New("not implemented")
}
