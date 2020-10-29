package sgw

import (
	"net"
)

type SessionEvent interface{}

type SessionEventHandler = func(s Session, ev SessionEvent)

type SessionCreateSessionResponseEvent struct{ Error error }
type SessionDeleteSessionResponseEvent struct{ Error error }
type SessionModifyBearerResponseEvent struct{ Error error }
type SessionTunnelStartEvent struct{}
type SessionTunnelStopEvent struct{}
type SessionIncomingTPDUEvent struct {
	Data    []byte
	PeerSrc *net.UDPAddr
}
