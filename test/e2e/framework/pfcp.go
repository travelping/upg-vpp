package framework

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type pfcpState string
type pfcpEvent string

type sessionState string
type sessionEvent string

type SEID uint64

const (
	PFCP_BUF_SIZE = 100000
	PFCP_PORT     = 8805

	ApplyAction_FORW = 2
	UEIPAddress_SD   = 4
	UEIPAddress_V4   = 2
	UEIPAddress_V6   = 1

	AssociationTimeout          = 10 * time.Second
	SessionEstablishmentTimeout = 10 * time.Second
	SessionModificationTimeout  = 10 * time.Second
	PFCPStopTimeout             = 15 * time.Second

	pfcpStateInitial              pfcpState = "INITIAL"
	pfcpStateFailed               pfcpState = "FAILED"
	pfcpStateAssociating          pfcpState = "ASSOCIATING"
	pfcpStateAssociated           pfcpState = "ASSOCIATED"
	pfcpStateReleasingAssociation pfcpState = "RELEASING_ASSOCIATION"
	pfcpStateCancelAssociation    pfcpState = "CANCEL_ASSOCIATION"

	pfcpEventNone                         pfcpEvent = ""
	pfcpEventTimeout                      pfcpEvent = "TIMEOUT"
	pfcpEventAssociationSetupResponse     pfcpEvent = "ASSOCIATION_SETUP_RESPONSE"
	pfcpEventAssociationReleaseResponse   pfcpEvent = "ASSOCIATION_RELEASE_RESPONSE"
	pfcpEventSessionEstablishmentResponse pfcpEvent = "SESSION_ESTABLISHMENT_REQUEST"
	pfcpEventSessionModificationResponse  pfcpEvent = "SESSION_MODIFICATION_RESPONSE"
	pfcpEventSessionDeletionResponse      pfcpEvent = "SESSION_DELETION_RESPONSE"
	pfcpEventHeartbeatRequest             pfcpEvent = "HEARTBEAT_REQUEST"
	pfcpEventActBegin                     pfcpEvent = "ACTION_BEGIN"
	pfcpEventActStop                      pfcpEvent = "ACTION_STOP"
	pfcpEventActEstablishSession          pfcpEvent = "ACTION_ESTABLISH_SESSION"
	pfcpEventActModifySession             pfcpEvent = "ACTION_MODIFY_SESSION"
	pfcpEventActDeleteSession             pfcpEvent = "ACTION_DELETE_SESSION"

	sessionStateEstablishing sessionState = "ESTABLISHING"
	sessionStateEstablished  sessionState = "ESTABLISHED"
	sessionStateModifying    sessionState = "MODIFYING"
	sessionStateDeleting     sessionState = "DELETING"
	sessionStateDeleted      sessionState = "DELETED"
	sessionStateFailed       sessionState = "FAILED"

	sessionEventEstablished sessionEvent = "ESTABLISHED"
	sessionEventModified    sessionEvent = "MODIFIED"
	sessionEventDeleted     sessionEvent = "DELETED"
	sessionEventActModify   sessionEvent = "MODIFY"
	sessionEventActDelete   sessionEvent = "DELETE"
)

var (
	errUnexpected       = errors.New("unexpected pfcp message")
	errHeartbeatTimeout = errors.New("heartbeat timeout")
)

type pfcpTransitionFunc func(pc *PFCPConnection, m message.Message) error

var pfcpIgnore pfcpTransitionFunc = func(pc *PFCPConnection, m message.Message) error { return nil }

func pfcpSessionRequest(event sessionEvent) pfcpTransitionFunc {
	return func(pc *PFCPConnection, m message.Message) error {
		if err := pc.sessionEvent(event, m); err != nil {
			return err
		}
		return pc.sendRequest(m)
	}
}

func pfcpSessionResponse(event sessionEvent) pfcpTransitionFunc {
	return func(pc *PFCPConnection, m message.Message) error {
		if handled, err := pc.acceptResponse(m); err != nil {
			return err
		} else if handled {
			return pc.sessionEvent(event, m)
		}

		return nil
	}
}

type pfcpTransitionKey struct {
	state pfcpState
	event pfcpEvent
}

var pfcpTransitions = map[pfcpTransitionKey]pfcpTransitionFunc{
	{pfcpStateInitial, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, m message.Message) error {
		return pc.sendHeartbeatResponse(m.(*message.HeartbeatRequest))
	},

	{pfcpStateInitial, pfcpEventActBegin}: func(pc *PFCPConnection, m message.Message) error {
		pc.setState(pfcpStateAssociating)
		return pc.sendAssociationSetupRequest()
	},

	{pfcpStateAssociating, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, m message.Message) error {
		return pc.sendHeartbeatResponse(m.(*message.HeartbeatRequest))
	},

	{pfcpStateAssociating, pfcpEventAssociationSetupResponse}: func(pc *PFCPConnection, m message.Message) error {
		if handled, err := pc.acceptResponse(m); err != nil {
			return err
		} else if handled {
			pc.setTimeout(pc.cfg.HeartbeatTimeout)
			pc.setState(pfcpStateAssociated)
		}
		return nil
	},

	{pfcpStateAssociating, pfcpEventActStop}: func(pc *PFCPConnection, m message.Message) error {
		pc.setState(pfcpStateCancelAssociation)
		return nil
	},

	{pfcpStateCancelAssociation, pfcpEventAssociationSetupResponse}: func(pc *PFCPConnection, m message.Message) error {
		if handled, err := pc.acceptResponse(m); err != nil {
			return err
		} else if handled {
			// TODO: delete all the active sessions
			pc.setState(pfcpStateInitial)
			pc.rq.clear()
			pc.notifyDone()
			return nil
		}
		return nil
	},

	{pfcpStateAssociating, pfcpEventTimeout}: func(pc *PFCPConnection, m message.Message) error {
		return errHeartbeatTimeout
	},

	{pfcpStateAssociated, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, m message.Message) error {
		pc.setTimeout(pc.cfg.HeartbeatTimeout)
		return pc.sendHeartbeatResponse(m.(*message.HeartbeatRequest))
	},

	{pfcpStateAssociated, pfcpEventActStop}: func(pc *PFCPConnection, m message.Message) error {
		// TODO: delete all the active sessions
		pc.setState(pfcpStateInitial)
		pc.rq.clear()
		pc.notifyDone()
		return nil
	},

	{pfcpStateAssociated, pfcpEventActEstablishSession}: func(pc *PFCPConnection, m message.Message) error {
		seid, err := cpfseid(m)
		if err != nil {
			return errors.Wrap(err, "error creating session")
		}
		if err := pc.createSession(seid); err != nil {
			return errors.Wrap(err, "error creating session")
		}
		return pc.sendRequest(m)
	},

	{pfcpStateAssociated, pfcpEventActModifySession}: pfcpSessionRequest(sessionEventActModify),

	{pfcpStateAssociated, pfcpEventActDeleteSession}: pfcpSessionRequest(sessionEventActDelete),

	{pfcpStateAssociated, pfcpEventSessionEstablishmentResponse}: pfcpSessionResponse(sessionEventEstablished),

	{pfcpStateAssociated, pfcpEventSessionModificationResponse}: pfcpSessionResponse(sessionEventModified),

	{pfcpStateAssociated, pfcpEventSessionDeletionResponse}: pfcpSessionResponse(sessionEventDeleted),

	/* TODO: do association release (not handled by UPG ATM)
	{pfcpStateReleasingAssociation, pfcpEventActStop}: pfcpIgnore,

	{pfcpStateReleasingAssociation, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, m message.Message) error {
		return pc.sendHeartbeatResponse(m.(*message.HeartbeatRequest))
	},

	{pfcpStateReleasingAssociation, pfcpEventAssociationReleaseResponse}: func(pc *PFCPConnection, m message.Message) error {
		if handled, err := pc.acceptResponse(m); err != nil {
			return err
		} else if handled {
			pc.setState(pfcpStateInitial)
		}
		pc.notifyDone()
		return nil
	},
	*/
}

type PFCPConfig struct {
	Namespace *NetNS
	UNodeIP   net.IP
	// TODO: UEIP should be per-session
	UEIP             net.IP
	NodeID           string
	RequestTimeout   time.Duration
	HeartbeatTimeout time.Duration
}

func (cfg *PFCPConfig) setDefaults() {
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 3 * time.Second
	}
	if cfg.HeartbeatTimeout == 0 {
		cfg.HeartbeatTimeout = 30 * time.Second
	}
}

type PFCPConnection struct {
	sync.Mutex
	cfg         PFCPConfig
	conn        *net.UDPConn
	seq         uint32
	state       pfcpState
	timestamp   time.Time
	timer       *time.Timer
	rq          *requestQueue
	listenErrCh chan error
	done        bool
	wakeupCh    chan struct{}
	errCh       chan error
	Running     bool
	sessions    map[SEID]*pfcpSession

	// TODO: use a single event channel instead of these 3
	stopCh    chan struct{}
	messageCh chan message.Message
	requestCh chan message.Message
}

type PFCPReport struct {
	UplinkVolume   *uint64
	DownlinkVolume *uint64
	TotalVolume    *uint64
	Duration       *time.Duration
}

func (ms PFCPReport) String() string {
	s := "<PFCPReport"
	if ms.UplinkVolume != nil {
		s += fmt.Sprintf(" uplink=%d", *ms.UplinkVolume)
	}
	if ms.DownlinkVolume != nil {
		s += fmt.Sprintf(" downlink=%d", *ms.DownlinkVolume)
	}
	if ms.TotalVolume != nil {
		s += fmt.Sprintf(" total=%d", *ms.TotalVolume)
	}
	if ms.Duration != nil {
		s += fmt.Sprintf(" duration=%v", ms.Duration)
	}
	s += ">"
	return s
}

type PFCPMeasurement struct {
	Reports   map[uint32]PFCPReport
	Timestamp time.Time
}

func NewPFCPConnection(cfg PFCPConfig) *PFCPConnection {
	cfg.setDefaults()
	return &PFCPConnection{
		cfg: cfg,
	}
}

func (pc *PFCPConnection) setState(newState pfcpState) {
	pc.state = newState
}

func (pc *PFCPConnection) setTimeout(d time.Duration) {
	if pc.timer != nil {
		pc.timer.Stop()
	}
	// create a new timer so there's no need to drain its channel
	// before Reset()
	pc.timer = time.NewTimer(d)
}

func (pc *PFCPConnection) wakeup() {
	select {
	case pc.wakeupCh <- struct{}{}:
	default:
		panic("wakeup channel full")
	}
}

func (pc *PFCPConnection) log(format string, args ...interface{}) {
	fmt.Printf(" * "+format+"\n", args...)
}

func (pc *PFCPConnection) event(event pfcpEvent, m message.Message) error {
	pc.Lock()
	oldState := pc.state
	defer func() {
		if oldState == pc.state {
			pc.log("%s: %s", oldState, event)
		} else {
			pc.log("%s: %s -> %s", oldState, event, pc.state)
		}
		pc.Unlock()
		pc.wakeup()
	}()
	tk := pfcpTransitionKey{state: pc.state, event: event}
	tf, found := pfcpTransitions[tk]
	if !found {
		pc.state = pfcpStateFailed
		return errors.Errorf("can't handle event %s in state %s", event, pc.state)
	}

	if err := tf(pc, m); err != nil {
		pc.state = pfcpStateFailed
		return err
	}

	return nil
}

func (pc *PFCPConnection) run() error {
	var err error
	if err = pc.dial(); err != nil {
		return err
	}
	defer pc.close()

	if err := pc.event(pfcpEventActBegin, nil); err != nil {
		return err
	}

	var retransmitTimer *time.Timer
LOOP:
	for !pc.done {
		var timerCh <-chan time.Time
		if pc.timer != nil {
			timerCh = pc.timer.C
		}

		now := time.Now()
		var retransmitCh <-chan time.Time
		// do all of the retransmits that are already due
	RETRANS_LOOP:
		for {
			nextRetransmitMsg, ts := pc.rq.next()
			switch {
			case nextRetransmitMsg == nil:
				// ok, no retransmits for now
				break RETRANS_LOOP
			case !ts.After(now):
				pc.log("retransmit %s", nextRetransmitMsg.MessageTypeName())
				pc.send(nextRetransmitMsg)
				pc.rq.reschedule(nextRetransmitMsg, now)
				continue
			case retransmitTimer != nil:
				if !retransmitTimer.Stop() {
					<-retransmitTimer.C
				}
				retransmitTimer.Reset(ts.Sub(now))
				retransmitCh = retransmitTimer.C
			default:
				retransmitTimer = time.NewTimer(ts.Sub(now))
				retransmitCh = retransmitTimer.C
			}
			break
		}

		select {
		case <-retransmitCh:
			// proceed to next iteration to handle the retransmits
		case msg := <-pc.requestCh:
			if ev, ok := requestToEvent(msg); ok {
				err = pc.event(ev, msg)
			} else {
				err = errors.New("unhandled message type")
			}
			if err != nil {
				err = errors.Wrapf(err, "error handling request %s in state %s", msg.MessageTypeName(), pc.state)
				break LOOP
			}
		case msg := <-pc.messageCh:
			pc.log("RECEIVE: %s seq %d SEID %016x", msg.MessageTypeName(), msg.Sequence(), msg.SEID())
			if ev, ok := peerMessageToEvent(msg); ok {
				err = pc.event(ev, msg)
			} else {
				err = errors.New("unhandled message type")
			}
			if err != nil {
				err = errors.Wrapf(err, "error handling peer message %s in state %s", msg.MessageTypeName(), pc.state)
				break LOOP
			}
		case <-timerCh:
			if err = pc.event(pfcpEventTimeout, nil); err != nil {
				err = errors.Wrapf(err, "timeout in state %s", pc.state)
				break LOOP
			}
		case <-pc.stopCh:
			if err = pc.event(pfcpEventActStop, nil); err != nil {
				err = errors.Wrapf(err, "stop in state %s", pc.state)
				break LOOP
			}
		case err = <-pc.listenErrCh:
			pc.log("* Listener error: %v", err)
			break LOOP
		}
	}

	return err
}

func (pc *PFCPConnection) notifyDone() {
	pc.done = true
}

func (pc *PFCPConnection) inState(state pfcpState) bool {
	pc.Lock()
	defer pc.Unlock()
	return pc.state == state
}

func (pc *PFCPConnection) waitForState(ctx context.Context, state pfcpState, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for !pc.inState(state) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			pc.Stop(ctx)
			return errors.New("session setup timeout")
		case err := <-pc.errCh:
			if err != nil {
				return err
			} else {
				return errors.New("PFCPConnection stopped prematurely (?)")
			}
		case <-pc.wakeupCh:
		}
	}

	return nil
}

func (pc *PFCPConnection) sessionInState(seid SEID, state sessionState) bool {
	pc.Lock()
	defer pc.Unlock()
	s, found := pc.sessions[seid]
	if !found {
		return false
	}
	return s.state == state
}

func (pc *PFCPConnection) waitForSessionState(ctx context.Context, seid SEID, state sessionState, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for !pc.sessionInState(seid, state) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			pc.Stop(ctx)
			return errors.New("session setup timeout")
		case err := <-pc.errCh:
			if err != nil {
				return err
			} else {
				return errors.New("PFCPConnection stopped prematurely (?)")
			}
		case <-pc.wakeupCh:
		}
	}

	return nil
}

func (pc *PFCPConnection) getSessionModCh(seid SEID) chan *PFCPMeasurement {
	pc.Lock()
	defer pc.Unlock()
	s, found := pc.sessions[seid]
	if !found {
		return nil
	}
	return s.modCh
}

func (pc *PFCPConnection) waitForSessionModification(ctx context.Context, seid SEID, ies ...ie.IE) (*PFCPMeasurement, error) {
	modCh := pc.getSessionModCh(seid)
	if modCh == nil {
		return nil, errors.Errorf("session %016x not found", seid)
	}

	timer := time.NewTimer(SessionModificationTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errors.Errorf("session modification timed out for %016x", seid)
	case err := <-pc.errCh:
		if err != nil {
			return nil, err
		} else {
			return nil, errors.New("PFCPConnection stopped prematurely (?)")
		}
	case ms := <-modCh:
		return ms, nil
	}
}

func (pc *PFCPConnection) dial() error {
	var err error
	pc.conn, err = pc.cfg.Namespace.DialUDP(
		&net.UDPAddr{
			IP:   pc.cfg.Namespace.IPNet.IP,
			Port: PFCP_PORT,
		},
		&net.UDPAddr{
			IP:   pc.cfg.UNodeIP,
			Port: PFCP_PORT,
		})
	if err != nil {
		return errors.Wrapf(err, "Dial UDP %s", pc.cfg.UNodeIP)
	}

	go func() {
		buf := make([]byte, PFCP_BUF_SIZE)
		for {
			n, addr, err := pc.conn.ReadFrom(buf)
			if err != nil {
				pc.listenErrCh <- errors.Wrap(err, "ReadFrom")
				break
			}

			msg, err := message.Parse(buf[:n])
			if err != nil {
				pc.listenErrCh <- errors.Wrapf(err, "error decoding message from %s", addr)
				break
			}

			pc.messageCh <- msg
		}
	}()

	return nil
}

func (pc *PFCPConnection) close() error {
	if pc.conn == nil {
		return nil
	}
	pc.conn.Close()
	pc.conn = nil
	return nil
}

func (pc *PFCPConnection) sendRequest(m message.Message) error {
	m.(pfcpRequest).SetSequenceNumber(pc.seq)
	pc.rq.add(m, time.Now())
	pc.seq++
	return pc.send(m)
}

func (pc *PFCPConnection) send(m message.Message) error {
	pc.log("SEND: %s seq %d SEID %016x", m.MessageTypeName(), m.Sequence(), m.SEID())
	bs := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(bs); err != nil {
		return errors.Wrap(err, "marshal pfcp message")
	}

	if _, err := pc.conn.Write(bs); err != nil {
		return errors.Wrap(err, "send pfcp message")
	}

	return nil
}

func (pc *PFCPConnection) acceptResponse(m message.Message) (bool, error) {
	if !pc.rq.remove(m) {
		pc.log("WARNING: skipping %s with wrong seq (%d instead of %d)",
			m.MessageTypeName(), m.Sequence(), pc.seq)
		return false, nil
	}
	if err := verifyCause(m); err != nil {
		return true, errors.Wrapf(err, "%s", m.MessageTypeName())
	}
	return true, nil
}

func (pc *PFCPConnection) sendAssociationSetupRequest() error {
	return pc.sendRequest(message.NewAssociationSetupRequest(
		0,
		ie.NewRecoveryTimeStamp(pc.timestamp),
		ie.NewNodeID("", "", pc.cfg.NodeID)))
}

/* TODO: not handled by UPG atm
func (pc *PFCPConnection) sendAssociationReleaseRequest() error {
	return pc.sendRequest(message.NewAssociationReleaseRequest(
		0, ie.NewNodeID("", "", pc.cfg.NodeID)))
}
*/

func (pc *PFCPConnection) sendHeartbeatResponse(hr *message.HeartbeatRequest) error {
	return pc.send(message.NewHeartbeatResponse(hr.SequenceNumber, ie.NewRecoveryTimeStamp(pc.timestamp)))
}

func (pc *PFCPConnection) createSession(seid SEID) error {
	_, found := pc.sessions[seid]
	if found {
		return errors.Errorf("session with SEID 0x%016x already present", seid)
	}
	pc.sessions[seid] = &pfcpSession{
		pc:    pc,
		seid:  seid,
		state: sessionStateEstablishing,
		modCh: make(chan *PFCPMeasurement, 10),
	}
	return nil
}

func (pc *PFCPConnection) sessionEvent(event sessionEvent, m message.Message) error {
	if m.SEID() == 0 {
		return errors.Errorf("no SEID in %s", m.MessageTypeName())
	}

	s, found := pc.sessions[SEID(m.SEID())]
	if !found {
		return errors.Errorf("error looking up the session with SEID %016x", m.SEID())
	}

	return s.event(event, m)
}

func (pc *PFCPConnection) newSEID() SEID {
	pc.Lock()
	defer pc.Unlock()
	for {
		seid := SEID(rand.Uint64())
		_, found := pc.sessions[seid]
		if !found {
			return seid
		}
	}
}

func (pc *PFCPConnection) Start(ctx context.Context) error {
	if pc.Running {
		return nil
	}

	pc.conn = nil
	pc.messageCh = make(chan message.Message, 1)
	pc.requestCh = make(chan message.Message, 1)
	pc.listenErrCh = make(chan error, 1)
	pc.timestamp = time.Now()
	pc.seq = 1
	pc.rq = newRequestQueue(pc.cfg.RequestTimeout)

	pc.done = false
	pc.state = pfcpStateInitial
	pc.sessions = make(map[SEID]*pfcpSession)

	pc.Running = true
	pc.stopCh = make(chan struct{})
	pc.wakeupCh = make(chan struct{}, 10000)
	pc.errCh = make(chan error)
	go func() {
		pc.errCh <- pc.run()
	}()

	return pc.waitForState(ctx, pfcpStateAssociated, AssociationTimeout)
}

func (pc *PFCPConnection) Stop(ctx context.Context) error {
	if !pc.Running {
		return nil
	}
	if pc.stopCh == nil {
		panic("Start() not called")
	}
	close(pc.stopCh)
	pc.stopCh = nil
	pc.Running = true

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(PFCPStopTimeout):
		return errors.New("timed out stopping PFCPConnection")
	case err := <-pc.errCh:
		return err
	}
}

func (pc *PFCPConnection) EstablishSession(ctx context.Context, ies ...*ie.IE) (SEID, error) {
	seid := pc.newSEID()
	ies = append(ies,
		// TODO: replace for IPv6
		ie.NewFSEID(uint64(seid), pc.cfg.Namespace.IPNet.IP, nil, nil),
		ie.NewNodeID("", "", pc.cfg.NodeID))
	pc.requestCh <- message.NewSessionEstablishmentRequest(0, 0, 0, 0, 0, ies...)
	return seid, pc.waitForSessionState(ctx, seid, sessionStateEstablished, SessionEstablishmentTimeout)
}

func (pc *PFCPConnection) ModifySession(ctx context.Context, seid SEID, ies ...*ie.IE) (*PFCPMeasurement, error) {
	pc.requestCh <- message.NewSessionModificationRequest(0, 0, uint64(seid), 0, 0, ies...)
	return pc.waitForSessionModification(ctx, seid)
}

func (pc *PFCPConnection) DeleteSession(ctx context.Context, seid SEID, ies ...*ie.IE) (*PFCPMeasurement, error) {
	pc.requestCh <- message.NewSessionDeletionRequest(0, 0, uint64(seid), 0, 0, ies...)
	if err := pc.waitForSessionState(ctx, seid, sessionStateDeleted, SessionEstablishmentTimeout); err != nil {
		return nil, err
	}

	modCh := pc.getSessionModCh(seid)
	if modCh == nil {
		panic("modCh must not be nil!")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ms := <-modCh:
		return ms, nil
	default:
		panic("incorrect session deletion")
	}
}

type sessionTransitionFunc func(s *pfcpSession, m message.Message) error

func sessionToState(newState sessionState) sessionTransitionFunc {
	return func(s *pfcpSession, m message.Message) error {
		s.setState(newState)
		return nil
	}
}

type sessionTransitionKey struct {
	state sessionState
	event sessionEvent
}

var sessionTransitions = map[sessionTransitionKey]sessionTransitionFunc{
	{sessionStateEstablishing, sessionEventEstablished}: sessionToState(sessionStateEstablished),
	{sessionStateEstablished, sessionEventActDelete}:    sessionToState(sessionStateDeleting),
	{sessionStateEstablished, sessionEventActModify}:    sessionToState(sessionStateModifying),
	{sessionStateModifying, sessionEventModified}: func(s *pfcpSession, m message.Message) error {
		s.setState(sessionStateEstablished)
		return s.postMeasurement(m)
	},
	{sessionStateDeleting, sessionEventDeleted}: func(s *pfcpSession, m message.Message) error {
		s.setState(sessionStateDeleted)
		return s.postMeasurement(m)
	},
}

type pfcpSession struct {
	pc    *PFCPConnection
	seid  SEID
	state sessionState
	modCh chan *PFCPMeasurement
}

func (s *pfcpSession) setState(newState sessionState) {
	s.state = newState
}

func (s *pfcpSession) event(event sessionEvent, m message.Message) error {
	oldState := s.state
	defer func() {
		if oldState == s.state {
			s.pc.log("Session %016x: %s: %s", s.seid, oldState, event)
		} else {
			s.pc.log("Session %016x: %s: %s -> %s", s.seid, oldState, event, s.state)
		}
	}()
	tk := sessionTransitionKey{state: s.state, event: event}
	tf, found := sessionTransitions[tk]
	if !found {
		s.state = sessionStateFailed
		return errors.Errorf("Session %016x: can't handle event %s in state %s", s.seid, event, s.state)
	}

	if err := tf(s, m); err != nil {
		s.state = sessionStateFailed
		return err
	}

	return nil
}

func (s *pfcpSession) postMeasurement(m message.Message) error {
	var urs []*ie.IE
	switch m.MessageType() {
	case message.MsgTypeSessionModificationResponse:
		urs = m.(*message.SessionModificationResponse).UsageReport
	case message.MsgTypeSessionDeletionResponse:
		urs = m.(*message.SessionDeletionResponse).UsageReport
	default:
		panic("bad message type")
	}

	if len(urs) == 0 {
		s.modCh <- nil
		return nil
	}

	ms := PFCPMeasurement{
		Timestamp: time.Now(),
		Reports:   make(map[uint32]PFCPReport),
	}

	for _, ur := range urs {
		r := PFCPReport{}

		urridIE, err := ur.FindByType(ie.URRID)
		if err != nil {
			return errors.Wrap(err, "can't find URR ID IE")
		}

		urrid, err := urridIE.URRID()
		if err != nil {
			return errors.Wrap(err, "can't parse URR ID IE")
		}

		volMeasurement, err := ur.FindByType(ie.VolumeMeasurement)
		if err != ie.ErrIENotFound {
			if err != nil {
				return errors.Wrap(err, "can't find VolumeMeasurement IE")
			}

			parsedVolMeasurement, err := volMeasurement.VolumeMeasurement()
			if err != nil {
				return errors.Wrap(err, "can't parse VolumeMeasurement IE")
			}

			if parsedVolMeasurement.HasDLVOL() {
				r.DownlinkVolume = &parsedVolMeasurement.DownlinkVolume
			}

			if parsedVolMeasurement.HasULVOL() {
				r.UplinkVolume = &parsedVolMeasurement.UplinkVolume
			}

			if parsedVolMeasurement.HasTOVOL() {
				r.TotalVolume = &parsedVolMeasurement.TotalVolume
			}
		}

		durMeasurement, err := ur.FindByType(ie.DurationMeasurement)
		if err != ie.ErrIENotFound {
			if err != nil {
				return errors.Wrap(err, "can't find DurationMeasurement IE")
			}

			duration, err := durMeasurement.DurationMeasurement()
			if err != nil {
				return errors.Wrap(err, "can't parse DurationMeasurement IE")
			}

			r.Duration = &duration
		}

		s.pc.log("%s: %s", m.MessageTypeName(), r)
		ms.Reports[urrid] = r
	}
	s.modCh <- &ms
	return nil
}

var causes = map[uint8]string{
	ie.CauseRequestAccepted:                 "RequestAccepted",
	ie.CauseRequestRejected:                 "RequestRejected",
	ie.CauseSessionContextNotFound:          "SessionContextNotFound",
	ie.CauseMandatoryIEMissing:              "MandatoryIEMissing",
	ie.CauseConditionalIEMissing:            "ConditionalIEMissing",
	ie.CauseInvalidLength:                   "InvalidLength",
	ie.CauseMandatoryIEIncorrect:            "MandatoryIEIncorrect",
	ie.CauseInvalidForwardingPolicy:         "InvalidForwardingPolicy",
	ie.CauseInvalidFTEIDAllocationOption:    "InvalidFTEIDAllocationOption",
	ie.CauseNoEstablishedPFCPAssociation:    "NoEstablishedPFCPAssociation",
	ie.CauseRuleCreationModificationFailure: "RuleCreationModificationFailure",
	ie.CausePFCPEntityInCongestion:          "PFCPEntityInCongestion",
	ie.CauseNoResourcesAvailable:            "NoResourcesAvailable",
	ie.CauseServiceNotSupported:             "ServiceNotSupported",
	ie.CauseSystemFailure:                   "SystemFailure",
	ie.CauseRedirectionRequested:            "RedirectionRequested",
}

func getCauseIE(m message.Message) *ie.IE {
	switch r := m.(type) {
	case *message.AssociationSetupResponse:
		return r.Cause
	case *message.AssociationReleaseResponse:
		return r.Cause
	case *message.AssociationUpdateResponse:
		return r.Cause
	case *message.NodeReportResponse:
		return r.Cause
	case *message.PFDManagementResponse:
		return r.Cause
	case *message.SessionEstablishmentResponse:
		return r.Cause
	case *message.SessionDeletionResponse:
		return r.Cause
	case *message.SessionModificationResponse:
		return r.Cause
	case *message.SessionReportResponse:
		return r.Cause
	case *message.SessionSetDeletionResponse:
		return r.Cause
	default:
		return nil
	}
}

func verifyCause(m message.Message) error {
	causeIE := getCauseIE(m)
	if causeIE == nil {
		return errors.New("no cause")
	}

	cause, err := causeIE.Cause()
	if err != nil {
		return errors.Wrap(err, "bad Cause IE")
	}

	if cause == ie.CauseRequestAccepted {
		return nil
	}

	s, found := causes[cause]
	if !found {
		return errors.Errorf("bad cause value %d", cause)
	}

	return errors.Errorf("failed, cause: %s", s)
}

func requestToEvent(m message.Message) (pfcpEvent, bool) {
	switch m.MessageType() {
	case message.MsgTypeSessionEstablishmentRequest:
		return pfcpEventActEstablishSession, true
	case message.MsgTypeSessionDeletionRequest:
		return pfcpEventActDeleteSession, true
	case message.MsgTypeSessionModificationRequest:
		return pfcpEventActModifySession, true
	default:
		return pfcpEventNone, false
	}
}

func peerMessageToEvent(m message.Message) (pfcpEvent, bool) {
	switch m.MessageType() {
	case message.MsgTypeAssociationSetupResponse:
		return pfcpEventAssociationSetupResponse, true
	case message.MsgTypeAssociationReleaseResponse:
		return pfcpEventAssociationReleaseResponse, true
	case message.MsgTypeSessionEstablishmentResponse:
		return pfcpEventSessionEstablishmentResponse, true
	case message.MsgTypeSessionModificationResponse:
		return pfcpEventSessionModificationResponse, true
	case message.MsgTypeSessionDeletionResponse:
		return pfcpEventSessionDeletionResponse, true
	case message.MsgTypeHeartbeatRequest:
		return pfcpEventHeartbeatRequest, true
	default:
		return pfcpEventNone, false
	}
}

func cpfseid(m message.Message) (SEID, error) {
	cpfseid := m.(*message.SessionEstablishmentRequest).CPFSEID
	if cpfseid == nil {
		return 0, errors.New("no CP-FSEID in SessionEstablishmentRequest")
	}
	fields, err := cpfseid.FSEID()
	if err != nil {
		return 0, errors.Wrap(err, "error parsing F-SEID for the session")
	}
	return SEID(fields.SEID), nil
}

type pfcpRequest interface {
	SetSequenceNumber(seq uint32)
}

// TODO: proper logging
