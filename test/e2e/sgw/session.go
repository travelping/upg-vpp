// session.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package sgw

import (
	"net"

	"github.com/sirupsen/logrus"
)

type Session interface {
	TriggerEvent(ev SessionEvent)
	UNodeAddr() *net.UDPAddr
	TEIDPGWs5u() uint32
	TEIDSGWs5u() uint32
	IPv4() net.IP
	IPv6() net.IP
	TunnelRegistered() bool
	SetTunnelRegistered(r bool)
	Logger() *logrus.Entry
}

type SimpleSessionConfig struct {
	UNodeAddr  *net.UDPAddr
	TEIDPGWs5u uint32
	TEIDSGWs5u uint32
	IPv4       net.IP
	IPv6       net.IP
	Logger     *logrus.Entry
}

type SimpleSession struct {
	cfg              SimpleSessionConfig
	tunnelRegistered bool
}

var _ Session = &SimpleSession{}

func NewSimpleSession(cfg SimpleSessionConfig) *SimpleSession {
	return &SimpleSession{cfg: cfg}
}

func (s *SimpleSession) TriggerEvent(ev SessionEvent) {}
func (s *SimpleSession) UNodeAddr() *net.UDPAddr      { return s.cfg.UNodeAddr }
func (s *SimpleSession) TEIDPGWs5u() uint32           { return s.cfg.TEIDPGWs5u }
func (s *SimpleSession) TEIDSGWs5u() uint32           { return s.cfg.TEIDSGWs5u }
func (s *SimpleSession) IPv4() net.IP                 { return s.cfg.IPv4 }
func (s *SimpleSession) IPv6() net.IP                 { return s.cfg.IPv6 }
func (s *SimpleSession) TunnelRegistered() bool       { return s.tunnelRegistered }
func (s *SimpleSession) SetTunnelRegistered(r bool)   { s.tunnelRegistered = r }
func (s *SimpleSession) Logger() *logrus.Entry        { return s.cfg.Logger }
