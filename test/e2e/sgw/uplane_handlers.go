// uplane_handlers.go - 3GPP TS 29.244 GTP-U UP plug-in
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

	"github.com/pkg/errors"

	"github.com/wmnsk/go-gtp/gtpv1/ie"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

func (up *UserPlaneServer) handleMessage(msg message.Message, src *net.UDPAddr) error {
	up.logger.Tracef("Received %T", msg.MessageTypeName())

	switch msg := msg.(type) {
	case *message.EchoRequest:
		return up.handleEchoRequest(msg, src)
	case *message.EchoResponse:
		return up.handleEchoResponse(msg)
	case *message.ErrorIndication:
		return up.handleErrorIndication(msg)
	case *message.TPDU:
		return up.handleTPDU(msg, src)
	default:
		return errors.Errorf("Missed handler for message %T", msg.MessageTypeName())
	}
}

func (up *UserPlaneServer) handleEchoRequest(msg *message.EchoRequest, src *net.UDPAddr) error {
	up.logger.Info("Received echo request. Sending echo response")
	return up.SendResponse(src, msg, message.NewEchoResponse(0, ie.NewRecovery(up.restartCounter)))
}

func (up *UserPlaneServer) handleEchoResponse(msg *message.EchoResponse) error {
	up.logger.Info("Received echo response")
	return nil
}

func (up *UserPlaneServer) handleErrorIndication(msg *message.ErrorIndication) error {
	up.logger.
		WithField("teid", msg.TEIDDataI.MustTEID()).
		WithField("ip", msg.GTPUPeerAddress.MustIP()).
		Warn("Received error indication")
	return nil
}

func (up *UserPlaneServer) handleTPDU(msg *message.TPDU, src *net.UDPAddr) error {
	if up.cfg.TPDUHook != nil {
		up.cfg.TPDUHook(msg, true)
	}

	teid := msg.TEID()
	if s := up.getSessionBySTEID(teid); s == nil {
		return errors.Errorf("Received TPDU for unknown session s5c_teid: 0x%.8x", teid)
	} else {
		s.TriggerEvent(&SessionIncomingTPDUEvent{
			Data: msg.Decapsulate(), PeerSrc: src,
		})
		if up.tunnel != nil {
			if err := up.tunnel.HandleTPDU(msg.Decapsulate(), src); err != nil {
				return errors.Wrap(err, "Failed to parse TPDU by tunnel")
			}
		}
	}
	return nil
}
