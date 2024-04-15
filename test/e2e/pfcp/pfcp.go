// pfcp.go - 3GPP TS 29.244 GTP-U UP plug-in
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

package pfcp

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"gopkg.in/tomb.v2"

	"github.com/travelping/upg-vpp/test/e2e/network"
	"github.com/travelping/upg-vpp/test/e2e/util"
)

type SessionOpSpec struct {
	SEID SEID
	IEs  []*ie.IE
}

type pfcpState string
type pfcpEventType string

type eventResult struct {
	cp_seid SEID
	payload interface{}
	err     error
}

type pfcpEvent struct {
	msg          message.Message
	eventType    pfcpEventType
	resultCh     chan eventResult
	attemptsLeft int
	// cp_seid is used in the requests that were not sent yet.  It's
	// needed b/c SessionEstablishmentRequest doesn't have the
	// session's SEID in it
	cp_seid SEID
	timerID timerID
}

func (e pfcpEvent) Sequence() uint32 {
	if e.msg == nil {
		return 0
	}
	return e.msg.Sequence()
}

type sessionState string
type sessionEventType string
type timerID int
type SEID uint64

const (
	PFCP_BUF_SIZE = 100000
	PFCP_PORT     = 8805

	ApplyAction_DROP = 1
	ApplyAction_FORW = 2
	UEIPAddress_SD   = 4
	UEIPAddress_V4   = 2
	UEIPAddress_V6   = 1

	OuterHeaderCreation_GTPUUDPIPV4 = 1 << 8
	OuterHeaderCreation_GTPUUDPIPV6 = 1 << 9

	OuterHeaderRemoval_GTPUUDPIPV4 = 0
	OuterHeaderRemoval_GTPUUDPIPV6 = 1

	ReportingTriggers_QUVTI = 0x0080 // Quota Validity Time
	ReportingTriggers_PERIO = 0x0100 // Periodic Reporting
	ReportingTriggers_VOLQU = 0x0001 // Volume Quota

	maxRequestAttempts = 10

	pfcpStateInitial              pfcpState = "INITIAL"
	pfcpStateFailed               pfcpState = "FAILED"
	pfcpStateAssociating          pfcpState = "ASSOCIATING"
	pfcpStateAssociated           pfcpState = "ASSOCIATED"
	pfcpStateReleasingAssociation pfcpState = "RELEASING_ASSOCIATION"
	pfcpStateCancelAssociation    pfcpState = "CANCEL_ASSOCIATION"

	pfcpEventNone                         pfcpEventType = ""
	pfcpEventTimeout                      pfcpEventType = "TIMEOUT"
	pfcpEventAssociationSetupResponse     pfcpEventType = "ASSOCIATION_SETUP_RESPONSE"
	pfcpEventAssociationReleaseResponse   pfcpEventType = "ASSOCIATION_RELEASE_RESPONSE"
	pfcpEventSessionEstablishmentResponse pfcpEventType = "SESSION_ESTABLISHMENT_REQUEST"
	pfcpEventSessionModificationResponse  pfcpEventType = "SESSION_MODIFICATION_RESPONSE"
	pfcpEventSessionDeletionResponse      pfcpEventType = "SESSION_DELETION_RESPONSE"
	pfcpEventSessionReportRequest         pfcpEventType = "SESSION_REPORT_REQUEST"
	pfcpEventHeartbeatRequest             pfcpEventType = "HEARTBEAT_REQUEST"
	pfcpEventActBegin                     pfcpEventType = "ACTION_BEGIN"
	pfcpEventActStop                      pfcpEventType = "ACTION_STOP"
	pfcpEventActEstablishSession          pfcpEventType = "ACTION_ESTABLISH_SESSION"
	pfcpEventActModifySession             pfcpEventType = "ACTION_MODIFY_SESSION"
	pfcpEventActDeleteSession             pfcpEventType = "ACTION_DELETE_SESSION"

	sessionStateNone         sessionState = ""
	sessionStateEstablishing sessionState = "ESTABLISHING"
	sessionStateEstablished  sessionState = "ESTABLISHED"
	sessionStateModifying    sessionState = "MODIFYING"
	sessionStateDeleting     sessionState = "DELETING"
	sessionStateDeleted      sessionState = "DELETED"
	sessionStateFailed       sessionState = "FAILED"

	sessionEventEstablished sessionEventType = "ESTABLISHED"
	sessionEventModified    sessionEventType = "MODIFIED"
	sessionEventDeleted     sessionEventType = "DELETED"
	sessionEventActModify   sessionEventType = "MODIFY"
	sessionEventActDelete   sessionEventType = "DELETE"

	timerIDHeartbeatTimeout timerID = iota
	timerIDRetransmit

	// This is hack to perform and validate CP SEID change on session migration in SMFSet
	// Session CP SEID will be increased on this value after migration
	CP_SEID_CHANGE_ON_SMF_MIGRATION SEID = 0x1_0000_000
)

var (
	errUnexpected       = errors.New("unexpected pfcp message")
	errHeartbeatTimeout = errors.New("heartbeat timeout")
	errHardStop         = errors.New("hard stop")
	causes              = map[uint8]string{
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
)

type PFCPServerError struct {
	Cause        uint8
	SEID         SEID
	FailedRuleID uint32
	Message      string
}

func (e *PFCPServerError) Error() string {
	s, found := causes[e.Cause]
	if !found {
		return fmt.Sprintf("<bad cause value %d>", e.Cause)
	}

	if e.Message != "" {
		return fmt.Sprintf("server error, cause: %s: %s", s, e.Message)
	}

	return fmt.Sprintf("server error, cause: %s", s)
}

type pfcpTransitionFunc func(pc *PFCPConnection, ev pfcpEvent) error

var pfcpIgnore pfcpTransitionFunc = func(pc *PFCPConnection, ev pfcpEvent) error { return nil }

func pfcpSessionRequest(et sessionEventType) pfcpTransitionFunc {
	return func(pc *PFCPConnection, ev pfcpEvent) error {
		if _, err := pc.sessionEvent(et, ev); err != nil {
			return err
		}
		return pc.sendRequest(ev)
	}
}

func pfcpSessionResponse(et sessionEventType) pfcpTransitionFunc {
	return func(pc *PFCPConnection, ev pfcpEvent) error {
		if reqEv, err := pc.acceptResponse(ev); err != nil {
			if reqEv != nil {
				reqEv.resultCh <- eventResult{
					cp_seid: reqEv.cp_seid,
					err:     err,
				}
			}
			var serverErr *PFCPServerError
			if errors.As(err, &serverErr) {
				s, found := pc.sessions[serverErr.SEID]
				if found {
					s.error(err)
				}
				// the association is still possibly fine
				return nil
			}
			return err
		} else if reqEv != nil {
			result, err := pc.sessionEvent(et, ev)
			reqEv.resultCh <- eventResult{
				cp_seid: reqEv.cp_seid,
				payload: result,
				err:     err,
			}
		}

		return nil
	}
}

type pfcpTransitionKey struct {
	state     pfcpState
	eventType pfcpEventType
}

var pfcpTransitions = map[pfcpTransitionKey]pfcpTransitionFunc{
	{pfcpStateInitial, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, ev pfcpEvent) error {
		pc.receivedHBRequestTimes = append(pc.receivedHBRequestTimes, time.Now())
		if pc.FITHook.IsFaultInjected(util.FaultIgnoreHeartbeat) {
			// ignore heartbeat requests, so UPG will drop
			// this association eventually
			return nil
		}
		return pc.sendHeartbeatResponse(ev.msg.(*message.HeartbeatRequest))
	},

	{pfcpStateInitial, pfcpEventActBegin}: func(pc *PFCPConnection, ev pfcpEvent) error {
		pc.setState(pfcpStateAssociating)
		return pc.sendAssociationSetupRequest()
	},

	{pfcpStateAssociating, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, ev pfcpEvent) error {
		pc.receivedHBRequestTimes = append(pc.receivedHBRequestTimes, time.Now())
		if pc.FITHook.IsFaultInjected(util.FaultIgnoreHeartbeat) {
			return nil
		}
		return pc.sendHeartbeatResponse(ev.msg.(*message.HeartbeatRequest))
	},

	{pfcpStateAssociating, pfcpEventAssociationSetupResponse}: func(pc *PFCPConnection, ev pfcpEvent) error {
		if reqEv, err := pc.acceptResponse(ev); err != nil {
			if reqEv != nil {
				reqEv.resultCh <- eventResult{err: err}
			}
			return err
		} else if reqEv != nil {
			pc.setTimeout(timerIDHeartbeatTimeout, pc.cfg.HeartbeatTimeout)
			pc.setState(pfcpStateAssociated)
			reqEv.resultCh <- eventResult{}
		}
		return nil
	},

	{pfcpStateAssociating, pfcpEventActStop}: func(pc *PFCPConnection, ev pfcpEvent) error {
		pc.setState(pfcpStateCancelAssociation)
		return nil
	},

	{pfcpStateCancelAssociation, pfcpEventAssociationSetupResponse}: func(pc *PFCPConnection, ev pfcpEvent) error {
		if reqEv, err := pc.acceptResponse(ev); err != nil {
			if reqEv != nil {
				reqEv.resultCh <- eventResult{err: err}
			}
			return err
		} else if reqEv != nil {
			pc.cleanAndDone()
			pc.setState(pfcpStateInitial)
			reqEv.resultCh <- eventResult{
				err: errors.New("association cancelled"),
			}
		}
		return nil
	},

	{pfcpStateAssociating, pfcpEventTimeout}: func(pc *PFCPConnection, ev pfcpEvent) error {
		if ev.timerID == timerIDHeartbeatTimeout {
			return errHeartbeatTimeout
		}
		return nil
	},

	{pfcpStateAssociated, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, ev pfcpEvent) error {
		pc.receivedHBRequestTimes = append(pc.receivedHBRequestTimes, time.Now())
		if pc.FITHook.IsFaultInjected(util.FaultIgnoreHeartbeat) {
			return nil
		}
		pc.setTimeout(timerIDHeartbeatTimeout, pc.cfg.HeartbeatTimeout)
		return pc.sendHeartbeatResponse(ev.msg.(*message.HeartbeatRequest))
	},

	{pfcpStateAssociated, pfcpEventTimeout}: func(pc *PFCPConnection, ev pfcpEvent) error {
		if ev.timerID == timerIDHeartbeatTimeout {
			pc.cleanAndDone()
			return errors.New("heartbeat timeout")
		}
		return nil
	},

	{pfcpStateAssociated, pfcpEventActStop}: func(pc *PFCPConnection, ev pfcpEvent) error {
		// TODO: delete all the active sessions
		pc.cleanAndDone()
		pc.setState(pfcpStateInitial)
		return nil
	},

	{pfcpStateAssociated, pfcpEventActEstablishSession}: func(pc *PFCPConnection, ev pfcpEvent) error {
		if err := pc.createSession(ev.cp_seid); err != nil {
			return errors.Wrap(err, "error creating session")
		}
		return pc.sendRequest(ev)
	},

	{pfcpStateAssociated, pfcpEventActModifySession}: pfcpSessionRequest(sessionEventActModify),

	{pfcpStateAssociated, pfcpEventActDeleteSession}: pfcpSessionRequest(sessionEventActDelete),

	{pfcpStateAssociated, pfcpEventSessionEstablishmentResponse}: pfcpSessionResponse(sessionEventEstablished),

	{pfcpStateAssociated, pfcpEventSessionModificationResponse}: pfcpSessionResponse(sessionEventModified),

	{pfcpStateAssociated, pfcpEventSessionDeletionResponse}: pfcpSessionResponse(sessionEventDeleted),

	{pfcpStateAssociated, pfcpEventSessionReportRequest}: func(pc *PFCPConnection, ev pfcpEvent) error {
		if pc.reportCh != nil {
			pc.log.Trace("captured SessionReportRequest")
			pc.reportCh <- ev.msg
		} else {
			pc.log.Warn("ignoring SessionReportRequest (no report channel)")
		}

		if pc.FITHook.IsFaultInjected(util.FaultSessionForgot) {
			return pc.sendSessionReportResponseFIT(ev.msg.(*message.SessionReportRequest))
		} else if pc.FITHook.IsFaultInjected(util.FaultNoReportResponse) {
			return nil
		} else {
			return pc.sendSessionReportResponse(ev.msg.(*message.SessionReportRequest))
		}
	},

	/* TODO: do association release (not handled by UPG ATM)
	{pfcpStateReleasingAssociation, pfcpEventActStop}: pfcpIgnore,

	{pfcpStateReleasingAssociation, pfcpEventHeartbeatRequest}: func(pc *PFCPConnection, ev pfcpEvent) error {
		pc.receivedHBRequestTimes = append(pc.receivedHBRequestTimes, time.Now())
		if pc.FITHook.IsFaultInjected(util.FaultIgnoreHeartbeat) {
			return nil
		}
		return pc.sendHeartbeatResponse(m.(*message.HeartbeatRequest))
	},

	{pfcpStateReleasingAssociation, pfcpEventAssociationReleaseResponse}: func(pc *PFCPConnection, ev pfcpEvent) error {
		if handled, err := pc.acceptResponse(ev.msg); err != nil {
			if ev.resultCh != nil {
				ev.resultCh <- eventResult{err: err}
			}
			return err
		} else if handled {
			pc.cleanAndDone()
			if ev.resultCh != nil {
				ev.resultCh <- eventResult{}
			}
		}
		return nil
	},
	*/
}

type PFCPConfig struct {
	Namespace         *network.NetNS
	CNodeIP           net.IP
	UNodeIP           net.IP
	NodeID            string
	RequestTimeout    time.Duration
	HeartbeatTimeout  time.Duration
	MaxInFlight       int
	InitialSeq        uint32
	RecoveryTimestamp time.Time
	SMFSet            string
	FITHook           *util.FITHook
}

func (cfg *PFCPConfig) setDefaults() {
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 3 * time.Second
	}
	if cfg.HeartbeatTimeout == 0 {
		cfg.HeartbeatTimeout = 30 * time.Second
	}
	if cfg.MaxInFlight == 0 {
		cfg.MaxInFlight = 100
	}
}

type PFCPConnection struct {
	sync.Mutex
	cfg                    PFCPConfig
	conn                   *net.UDPConn
	seq                    uint32
	state                  pfcpState
	timestamp              time.Time
	timer                  MultiTimer
	rq                     *requestQueue
	listenErrCh            chan error
	done                   bool
	sessions               map[SEID]*pfcpSession
	eventCh                chan pfcpEvent
	startCh                chan eventResult
	log                    *logrus.Entry
	t                      *tomb.Tomb
	skipMsgs               int
	reportCh               chan message.Message
	receivedHBRequestTimes []time.Time
	FITHook                *util.FITHook
}

type PFCPReport struct {
	UplinkVolume        *uint64
	DownlinkVolume      *uint64
	TotalVolume         *uint64
	UplinkPacketCount   *uint64
	DownlinkPacketCount *uint64
	TotalPacketCount    *uint64
	Duration            *time.Duration
	StartTime           time.Time
	EndTime             time.Time
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
	if ms.UplinkPacketCount != nil {
		s += fmt.Sprintf(" uplinkCount=%d", *ms.UplinkPacketCount)
	}
	if ms.DownlinkPacketCount != nil {
		s += fmt.Sprintf(" downlinkCount=%d", *ms.DownlinkPacketCount)
	}
	if ms.TotalPacketCount != nil {
		s += fmt.Sprintf(" totalCount=%d", *ms.TotalPacketCount)
	}
	if ms.Duration != nil {
		s += fmt.Sprintf(" duration=%v", ms.Duration)
	}
	s += ">"
	return s
}

type PFCPMeasurement struct {
	Reports   map[uint32][]PFCPReport
	Timestamp time.Time
}

func NewPFCPConnection(cfg PFCPConfig) *PFCPConnection {
	cfg.setDefaults()
	pc := &PFCPConnection{
		cfg:     cfg,
		log:     logrus.WithField("NodeID", cfg.NodeID),
		FITHook: cfg.FITHook,
	}
	return pc
}

func (pc *PFCPConnection) ReceivedHBRequestTimes() []time.Time {
	pc.Lock()
	defer pc.Unlock()
	r := make([]time.Time, len(pc.receivedHBRequestTimes))
	copy(r, pc.receivedHBRequestTimes)
	return r
}

func (pc *PFCPConnection) ShareSession(conn *PFCPConnection, seid SEID) error {
	if _, ok := conn.sessions[seid]; !ok {
		return errors.Errorf("No session %x in %+#v", seid, conn.sessions)
	}
	pc.sessions[seid] = conn.sessions[seid]
	return nil
}

func (pc *PFCPConnection) setState(newState pfcpState) {
	pc.state = newState
}

func (pc *PFCPConnection) setTimeout(id timerID, d time.Duration) {
	pc.timer.StartTimer(int(id), d)
}

func (pc *PFCPConnection) simpleEvent(eventType pfcpEventType) error {
	return pc.event(pfcpEvent{
		eventType: eventType,
	})
}

func (pc *PFCPConnection) event(event pfcpEvent) error {
	if event.resultCh != nil && event.msg == nil {
		panic("bad event with resultCh but no msg")
	}

	pc.Lock()

	var err error
	oldState := pc.state
	defer func() {
		if oldState == pc.state {
			pc.log.WithFields(logrus.Fields{
				"state": pc.state,
				"event": event.eventType,
			}).Trace("PFCP state machine event w/o transition")
		} else {
			pc.log.WithFields(logrus.Fields{
				"oldState": oldState,
				"event":    event.eventType,
				"newState": pc.state,
			}).Trace("PFCP state machine transition")
		}
		pc.Unlock()
	}()
	tk := pfcpTransitionKey{state: pc.state, eventType: event.eventType}
	tf, found := pfcpTransitions[tk]
	if !found {
		err = errors.Errorf("can't handle event %s in state %s", event.eventType, pc.state)
	}

	if err == nil {
		err = tf(pc, event)
	}

	if err != nil {
		pc.log.WithError(err).Error("entering FAILED state")
		pc.state = pfcpStateFailed
		pc.cleanAndDone()
		if event.resultCh != nil {
			event.resultCh <- eventResult{
				err:     err,
				cp_seid: event.cp_seid,
			}
		}

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

	if err := pc.simpleEvent(pfcpEventActBegin); err != nil {
		return err
	}

	dying := pc.t.Dying()
LOOP:
	for !pc.done {
		now := time.Now()
		// do all of the retransmits that are already due
	RETRANS_LOOP:
		for {
			e, ts := pc.rq.next()
			if e == nil && err == nil {
				// ok, no retransmits for now
				break
			}
			ev := e.(pfcpEvent)
			switch {
			case err != nil:
				pc.log.WithError(err).WithField("messageType", ev.msg.MessageTypeName()).
					Error("no retransmit attempts left")
				pc.t.Kill(err)
				break RETRANS_LOOP
			case !ts.After(now) && ev.attemptsLeft == 0:
				pc.log.WithField("messageType", ev.msg.MessageTypeName()).
					Error("out of retransmit attempts")
				err := errors.New("out of retransmit attempts")
				pc.t.Kill(err)
				break RETRANS_LOOP
			case !ts.After(now):
				pc.log.WithField("messageType", ev.msg.MessageTypeName()).
					Warn("retransmit")
				if err := pc.send(ev.msg); err != nil {
					pc.log.WithError(err).WithField("messageType", ev.msg.MessageTypeName()).Error("retransmit failed")
					pc.t.Kill(errors.Wrap(err, "retransmit failed"))
					break RETRANS_LOOP
				}
				ev.attemptsLeft--
				pc.rq.reschedule(ev, now)
				continue
			default:
				pc.setTimeout(timerIDRetransmit, ts.Sub(now))
			}
			break
		}

		select {
		case <-dying:
			pc.log.Info("stopping PFCP connection loop")
			dying = nil
			if pc.t.Err() == errHardStop {
				break LOOP
			}
			if err = pc.simpleEvent(pfcpEventActStop); err != nil {
				err = errors.Wrapf(err, "stop in state %s", pc.state)
				pc.log.WithError(err).Error("terminating the event loop")
				break LOOP
			}
		case id := <-pc.timer.Channel():
			tid := timerID(id)
			switch tid {
			case timerIDRetransmit:
				continue
			default:
				if err = pc.event(pfcpEvent{
					eventType: pfcpEventTimeout,
					timerID:   tid,
				}); err != nil {
					err = errors.Wrapf(err, "timeout in state %s", pc.state)
					pc.log.WithError(err).Error("terminating the event loop")
					break LOOP
				}

			}
			// proceed to next iteration to handle the retransmits
		case ev := <-pc.eventCh:
			cp_seid := ev.cp_seid
			if cp_seid == 0 {
				cp_seid = SEID(ev.msg.SEID())
			}
			pc.log.WithFields(logrus.Fields{
				"eventType":   ev.eventType,
				"messageType": ev.msg.MessageTypeName(),
				"seq":         ev.msg.Sequence(),
				"SEID":        fmt.Sprintf("%016x", cp_seid),
			}).Trace("incoming event")
			if err = pc.event(ev); err != nil {
				msgType := "<none>"
				if ev.msg != nil {
					msgType = ev.msg.MessageTypeName()
				}
				err = errors.Wrapf(err, "error handling event %s / msg type %s in state %s", ev.eventType, msgType, pc.state)
				pc.log.WithError(err).Error("terminating the event loop")
				break LOOP
			}
		case err = <-pc.listenErrCh:
			pc.log.WithError(err).Error("listener error")
			break LOOP
		}
	}

	pc.cleanAndDone()
	return err
}

func (pc *PFCPConnection) cleanAndDone() {
	err := errors.New("PFCP connection is closed")
LOOP:
	for {
		select {
		case ev := <-pc.eventCh:
			if ev.resultCh != nil {
				ev.resultCh <- eventResult{
					err:     err,
					cp_seid: ev.cp_seid,
				}
			}
		default:
			break LOOP
		}
	}

	// TODO: clear all of the active sessions
	for {
		e, _ := pc.rq.next()
		if e == nil {
			break
		}
		pc.rq.remove(e)
		ev := e.(pfcpEvent)
		if ev.resultCh != nil {
			ev.resultCh <- eventResult{
				err:     err,
				cp_seid: ev.cp_seid,
			}
		}
	}
	pc.rq.clear()
	pc.done = true
}

func (pc *PFCPConnection) shouldSkipMessage() bool {
	pc.Lock()
	defer pc.Unlock()
	if pc.skipMsgs > 0 {
		pc.skipMsgs--
		return true
	}

	return false
}

func (pc *PFCPConnection) AcquireReportCh() <-chan message.Message {
	pc.Lock()
	defer pc.Unlock()
	if pc.reportCh == nil {
		pc.reportCh = make(chan message.Message, 100)
	}
	return pc.reportCh
}

func (pc *PFCPConnection) SkipMessages(n int) {
	pc.Lock()
	defer pc.Unlock()
	pc.skipMsgs = n
}

func (pc *PFCPConnection) dial() error {
	var err error
	pc.conn, err = pc.cfg.Namespace.DialUDP(
		// We use IPs not hostnames in the tests, so no real
		// need for context here atm
		context.TODO(),
		&net.UDPAddr{
			IP:   pc.cfg.CNodeIP,
			Port: PFCP_PORT,
		},
		&net.UDPAddr{
			IP:   pc.cfg.UNodeIP,
			Port: PFCP_PORT,
		})
	if err != nil {
		return errors.Wrapf(err, "Dial UDP %s", pc.cfg.UNodeIP)
	}

	conn := pc.conn
	listenErrCh := pc.listenErrCh
	eventCh := pc.eventCh
	go func() {
		buf := make([]byte, PFCP_BUF_SIZE)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				listenErrCh <- errors.Wrap(err, "ReadFrom")
				break
			}

			// go-pfcp uses slices from the buffer we pass
			// to message.Parse, so we want to avoid overwriting
			// any stored messages
			// FIXME: need to make a new slice of just n bytes,
			// but that fails due to bugs in go-pfcp code
			bs := make([]byte, PFCP_BUF_SIZE)
			copy(bs, buf)
			msg, err := message.Parse(bs[:n])
			if err != nil {
				listenErrCh <- errors.Wrapf(err, "error decoding message from %s", addr)
				break
			}

			pc.log.WithFields(logrus.Fields{
				"messageType": msg.MessageTypeName(),
				"seq":         msg.Sequence(),
				"SEID":        fmt.Sprintf("%016x", msg.SEID()),
			}).Trace("receive")

			eventType, ok := peerMessageToEventType(msg)
			if !ok {
				listenErrCh <- errors.Errorf("unhandled message type %s", msg.MessageTypeName())
				break
			}

			if !pc.shouldSkipMessage() {
				eventCh <- pfcpEvent{
					eventType: eventType,
					msg:       msg,
				}
			} else {
				pc.log.WithField("messageType", msg.MessageTypeName()).Info("forced skip")
			}
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

func (pc *PFCPConnection) sendRequest(ev pfcpEvent) error {
	ev.msg.(pfcpRequest).SetSequenceNumber(pc.seq)
	pc.rq.add(ev, time.Now(), maxRequestAttempts)
	pc.seq++
	return pc.send(ev.msg)
}

func (pc *PFCPConnection) send(m message.Message) error {
	pc.log.WithFields(logrus.Fields{
		"messageType": m.MessageTypeName(),
		"seq":         m.Sequence(),
		"SEID":        fmt.Sprintf("%016x", m.SEID()),
	}).Trace("send")
	bs := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(bs); err != nil {
		return errors.Wrap(err, "marshal pfcp message")
	}

	if _, err := pc.conn.Write(bs); err != nil {
		return errors.Wrap(err, "send pfcp message")
	}

	return nil
}

func (pc *PFCPConnection) acceptResponse(ev pfcpEvent) (*pfcpEvent, error) {
	req := pc.rq.remove(ev)
	if req == nil {
		pc.log.WithFields(logrus.Fields{
			"messageType":  ev.msg.MessageTypeName(),
			"wrong_seq":    ev.msg.Sequence(),
			"expected_seq": pc.seq,
		}).Warn("skipping a message with wrong seq")
		return nil, nil
	}
	reqEv := (*req).(pfcpEvent)
	if err := verifyCause(ev.msg, SEID(reqEv.msg.SEID())); err != nil {
		return &reqEv, errors.Wrapf(err, "%s", ev.msg.MessageTypeName())
	}
	return &reqEv, nil
}

func (pc *PFCPConnection) sendAssociationSetupRequest() error {
	var ies []*ie.IE
	ies = append(ies,
		ie.NewRecoveryTimeStamp(pc.timestamp),
		ie.NewNodeID("", "", pc.cfg.NodeID),
	)
	if pc.cfg.SMFSet != "" {
		ies = append(ies, ie.NewSMFSetID(pc.cfg.SMFSet))
	}

	msg := message.NewAssociationSetupRequest(0, ies...)
	if err := pc.sendRequest(pfcpEvent{
		msg:          msg,
		resultCh:     pc.startCh,
		attemptsLeft: maxRequestAttempts,
	}); err != nil {
		return err
	}
	return nil
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

func (pc *PFCPConnection) sendSessionReportResponse(req *message.SessionReportRequest) error {
	var ies []*ie.IE
	var ses *pfcpSession
	var up_seid SEID

	ies = append(ies, ie.NewCause(ie.CauseRequestAccepted))

	// if migrated from old node
	if req.OldCPFSEID != nil {
		fseidFields, err := req.OldCPFSEID.FSEID()
		if err != nil {
			return err
		}
		ses = pc.sessions[SEID(fseidFields.SEID)]
		if ses != nil {
			// update CP SEID to validate change of node

			delete(pc.sessions, SEID(fseidFields.SEID))
			ses.cp_seid += CP_SEID_CHANGE_ON_SMF_MIGRATION
			pc.sessions[ses.cp_seid] = ses

			ies = append(ies, pc.NewIEFSEID(ses.cp_seid))

			up_seid = ses.up_seid
		}
	} else if sess := pc.sessions[SEID(req.SEID())]; sess != nil {
		up_seid = sess.up_seid
	} else {
		return pc.send(message.NewSessionReportResponse(0, 0, 0, req.SequenceNumber, 0, ie.NewCause(ie.CauseSessionContextNotFound)))
	}
	ies = append(ies, ie.NewRecoveryTimeStamp(pc.timestamp))
	return pc.send(message.NewSessionReportResponse(0, 0, uint64(up_seid), req.SequenceNumber, 0, ies...))
}

func (pc *PFCPConnection) sendSessionReportResponseFIT(req *message.SessionReportRequest) error {
	return pc.send(message.NewSessionReportResponse(
		0,
		0,
		0,
		req.SequenceNumber,
		0,
		ie.NewRecoveryTimeStamp(pc.timestamp),
		ie.NewCause(ie.CauseSessionContextNotFound),
	))
}

func (pc *PFCPConnection) createSession(seid SEID) error {
	_, found := pc.sessions[seid]
	if found {
		return errors.Errorf("session with SEID 0x%016x already present", seid)
	}
	pc.sessions[seid] = &pfcpSession{
		pc:      pc,
		cp_seid: seid,
		state:   sessionStateEstablishing,
	}
	return nil
}

func (pc *PFCPConnection) sessionFromMessage(m message.Message) (*pfcpSession, error) {
	if m.SEID() == 0 {
		return nil, errors.Errorf("no SEID in %s", m.MessageTypeName())
	}

	s, found := pc.sessions[SEID(m.SEID())]
	if !found {
		return nil, errors.Errorf("error looking up the session with SEID %016x", m.SEID())
	}

	return s, nil
}

func (pc *PFCPConnection) sessionEvent(et sessionEventType, ev pfcpEvent) (interface{}, error) {
	s, err := pc.sessionFromMessage(ev.msg)
	if err != nil {
		return nil, err
	}
	return s.event(et, ev)
}

func (pc *PFCPConnection) NewSEID() SEID {
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
	if pc.t != nil {
		return nil
	}

	pc.conn = nil
	pc.eventCh = make(chan pfcpEvent, 110000)
	pc.listenErrCh = make(chan error, 1)
	if pc.cfg.RecoveryTimestamp.IsZero() {
		pc.timestamp = time.Now()
	} else {
		pc.timestamp = pc.cfg.RecoveryTimestamp
	}
	pc.seq = pc.cfg.InitialSeq
	if pc.seq == 0 {
		pc.seq = 1
	}
	pc.rq = newRequestQueue(pc.cfg.RequestTimeout)

	pc.done = false
	pc.state = pfcpStateInitial
	pc.sessions = make(map[SEID]*pfcpSession)
	pc.startCh = make(chan eventResult)

	pc.t = &tomb.Tomb{}
	pc.t.Go(pc.run)

	// If no result is yielded within this interval, something is
	// broken in PFCPConnection code
	tch := time.After(pc.cfg.RequestTimeout * (maxRequestAttempts + 3))
	select {
	case r := <-pc.startCh:
		close(pc.startCh)
		return r.err
	case <-tch:
		return errors.New("Association Setup Request over timeout")
	}
}

func (pc *PFCPConnection) stop(err error) error {
	if pc.t == nil {
		return nil
	}

	pc.t.Kill(nil)
	err = pc.t.Wait()
	pc.t = nil
	return err
}

func (pc *PFCPConnection) Stop() error {
	return pc.stop(nil)
}

func (pc *PFCPConnection) HardStop() {
	pc.stop(errHardStop)
}

// ForgetSession forcibly removes the session entry
func (pc *PFCPConnection) ForgetSession(seid SEID) bool {
	pc.Lock()
	defer pc.Unlock()
	return pc.forgetSessionUnlocked(seid)
}

func (pc *PFCPConnection) forgetSessionUnlocked(seid SEID) bool {
	_, found := pc.sessions[seid]
	if !found {
		return false
	}
	delete(pc.sessions, seid)
	return true
}

func (pc *PFCPConnection) EstablishSession(ctx context.Context, seid SEID, ies ...*ie.IE) (SEID, error) {
	spec := SessionOpSpec{SEID: seid, IEs: ies}
	seids, errs := pc.EstablishSessions(ctx, []SessionOpSpec{spec})
	return seids[0], errs[0]
}

func (pc *PFCPConnection) EstablishSessions(ctx context.Context, specs []SessionOpSpec) ([]SEID, []error) {
	seids := make([]SEID, len(specs))
	reqs := make([]message.Message, len(specs))
	for n := range specs {
		spec := &specs[n]
		if spec.SEID == 0 {
			spec.SEID = pc.NewSEID()
		} else {
			// do not break existing session entry if creating a new
			// session with duplicate SEID is attempted without forgetting
			// the previous one using ForgetSession()
			pc.Lock()
			_, found := pc.sessions[spec.SEID]
			pc.Unlock()
			if found {
				panic("duplicate SEID used without forgetting")
			}
		}
		seids[n] = spec.SEID
		reqs[n] = pc.sessionEstablishmentRequest(*spec)
	}

	_, err := pc.pipelineRequests(ctx, specs, reqs, sessionStateEstablished)
	return seids, err
}

func (pc *PFCPConnection) ModifySession(ctx context.Context, seid SEID, ies ...*ie.IE) (*PFCPMeasurement, error) {
	spec := SessionOpSpec{SEID: seid, IEs: ies}
	ms, errs := pc.ModifySessions(ctx, []SessionOpSpec{spec})
	return ms[0], errs[0]
}

func (pc *PFCPConnection) ModifySessions(ctx context.Context, specs []SessionOpSpec) ([]*PFCPMeasurement, []error) {
	return pc.pipelineSessionRequests(
		ctx, specs, sessionStateEstablished, func(spec SessionOpSpec) message.Message {
			return message.NewSessionModificationRequest(0, 0, uint64(spec.SEID), 0, 0, spec.IEs...)
		})
}

func (pc *PFCPConnection) DeleteSession(ctx context.Context, seid SEID, ies ...*ie.IE) (*PFCPMeasurement, error) {
	spec := SessionOpSpec{SEID: seid, IEs: ies}
	ms, errs := pc.DeleteSessions(ctx, []SessionOpSpec{spec})
	return ms[0], errs[0]
}

func (pc *PFCPConnection) DeleteSessions(ctx context.Context, specs []SessionOpSpec) ([]*PFCPMeasurement, []error) {
	return pc.pipelineSessionRequests(
		ctx, specs, sessionStateNone, func(spec SessionOpSpec) message.Message {
			return message.NewSessionDeletionRequest(0, 0, uint64(spec.SEID), 0, 0, spec.IEs...)
		})
}

func (pc *PFCPConnection) pipelineSessionRequests(
	ctx context.Context,
	specs []SessionOpSpec,
	expectedSessionState sessionState,
	makeRequest func(spec SessionOpSpec) message.Message) ([]*PFCPMeasurement, []error) {
	reqs := make([]message.Message, len(specs))
	for n, spec := range specs {
		reqs[n] = makeRequest(spec)
	}

	results, errs := pc.pipelineRequests(ctx, specs, reqs, expectedSessionState)

	ms := make([]*PFCPMeasurement, len(specs))
	for n, r := range results {
		if r != nil {
			ms[n] = r.(*PFCPMeasurement)
		}
	}

	return ms, errs
}

func (pc *PFCPConnection) pipelineRequests(
	ctx context.Context,
	specs []SessionOpSpec,
	reqs []message.Message,
	expectedSessionState sessionState) ([]interface{}, []error) {
	errs := make([]error, len(specs))
	m := make(map[SEID]int)
	resultCh := make(chan eventResult, len(reqs))
	inFlight := 0
	cur := 0
	results := make([]interface{}, len(specs))
	// For len(specs) == 1:
	// If no result is yielded within this interval, something is
	// broken in PFCPConnection code.
	// TODO: fix head-of-line blocking problem with the request queue,
	// then remove/adjust " * time.Duration(len(specs))"
	tch := time.After(pc.cfg.RequestTimeout * (maxRequestAttempts + 3) *
		time.Duration(len(specs)))

	for cur < len(specs) || inFlight > 0 {
		for ; cur < len(specs) && inFlight < pc.cfg.MaxInFlight; cur++ {
			pc.log.WithFields(logrus.Fields{
				"cur":         cur,
				"inFlight":    inFlight,
				"messageType": reqs[cur].MessageTypeName(),
				"SEID":        fmt.Sprintf("%016x", specs[cur].SEID),
				"seq":         reqs[cur].Sequence(),
			}).Trace("enqueue")
			if err := pc.enqueueRequest(specs[cur].SEID, reqs[cur], resultCh); err != nil {
				errs[cur] = err
			} else {
				inFlight++
			}
			m[specs[cur].SEID] = cur
		}

		if inFlight == 0 {
			continue
		}
		var r eventResult
		select {
		case <-ctx.Done():
			// FIXME: should be able to cancel the requests that were not issued yet
			// For now, we just stop waiting as the cancellation is only used
			// when VPP dies.
			for n := range specs {
				errs[n] = ctx.Err()
			}
			return results, errs
		case r = <-resultCh:
		case <-tch:
			panic("pipelined request over timeout")
		}

		n, found := m[r.cp_seid]
		if !found {
			panic("Internal error: unexpected SEID in event response")
		}

		inFlight--
		if r.err != nil {
			errs[n] = errors.Wrapf(r.err, "SEID %016x", r.cp_seid)
		} else {
			results[n] = r.payload
		}
		pc.log.WithFields(logrus.Fields{
			"cur":      cur,
			"inFlight": inFlight,
			"SEID":     fmt.Sprintf("%016x", r.cp_seid),
			"err":      r.err,
			"seq":      reqs[n].Sequence(),
		}).Trace("response for a pipelined request")
	}

	return results, errs
}

func (pc *PFCPConnection) NewIEFSEID(seid SEID) *ie.IE {
	if pc.cfg.CNodeIP.To4() == nil {
		return ie.NewFSEID(uint64(seid), nil, pc.cfg.CNodeIP)
	} else {
		return ie.NewFSEID(uint64(seid), pc.cfg.CNodeIP.To4(), nil)
	}
}

func (pc *PFCPConnection) sessionEstablishmentRequest(spec SessionOpSpec) message.Message {
	fseid := pc.NewIEFSEID(spec.SEID)
	ies := append(spec.IEs, fseid, ie.NewNodeID("", "", pc.cfg.NodeID))
	return message.NewSessionEstablishmentRequest(0, 0, 0, 0, 0, ies...)
}

func (pc *PFCPConnection) enqueueRequest(seid SEID, msg message.Message, resultCh chan eventResult) error {
	if !pc.t.Alive() {
		return errors.Errorf("PFCPConnection not active: %s", pc.cfg.NodeID)
	}

	eventType, ok := requestToEventType(msg)
	if !ok {
		panic("bad request type")
	}

	pc.log.WithFields(logrus.Fields{
		"eventType":   eventType,
		"messageType": msg.MessageTypeName(),
		"seq":         msg.Sequence(),
		"SEID":        fmt.Sprintf("%016x", msg.SEID()),
	}).Trace("enqueue")

	pc.eventCh <- pfcpEvent{
		eventType:    eventType,
		msg:          msg,
		resultCh:     resultCh,
		attemptsLeft: maxRequestAttempts,
		cp_seid:      seid,
	}

	return nil
}

type sessionTransitionFunc func(s *pfcpSession, ev pfcpEvent) (*PFCPMeasurement, error)

func sessionToState(newState sessionState) sessionTransitionFunc {
	return func(s *pfcpSession, ev pfcpEvent) (*PFCPMeasurement, error) {
		s.setState(newState)
		return nil, nil
	}
}

type sessionTransitionKey struct {
	state sessionState
	event sessionEventType
}

var sessionTransitions = map[sessionTransitionKey]sessionTransitionFunc{
	{sessionStateEstablishing, sessionEventEstablished}: func(s *pfcpSession, ev pfcpEvent) (*PFCPMeasurement, error) {
		upFSEID, _ := ev.msg.(*message.SessionEstablishmentResponse).UPFSEID.FSEID()
		s.up_seid = SEID(upFSEID.SEID)
		s.setState(sessionStateEstablished)
		return nil, nil
	},
	{sessionStateEstablished, sessionEventActDelete}: sessionToState(sessionStateDeleting),
	{sessionStateEstablished, sessionEventActModify}: sessionToState(sessionStateModifying),
	{sessionStateModifying, sessionEventModified}: func(s *pfcpSession, ev pfcpEvent) (*PFCPMeasurement, error) {
		s.setState(sessionStateEstablished)
		return s.getMeasurement(ev.msg)
	},
	{sessionStateDeleting, sessionEventDeleted}: func(s *pfcpSession, ev pfcpEvent) (*PFCPMeasurement, error) {
		s.setState(sessionStateDeleted)
		s.removeSelf()
		return s.getMeasurement(ev.msg)
	},
	{sessionStateFailed, sessionEventActDelete}: func(s *pfcpSession, ev pfcpEvent) (*PFCPMeasurement, error) {
		// allow deleting failed sessions
		return nil, nil
	},
}

type pfcpSession struct {
	pc      *PFCPConnection
	cp_seid SEID
	up_seid SEID
	state   sessionState
}

func (s *pfcpSession) setState(newState sessionState) {
	s.state = newState
}

func (s *pfcpSession) removeSelf() {
	s.pc.forgetSessionUnlocked(s.cp_seid)
}

func (s *pfcpSession) error(err error) error {
	s.pc.log.WithFields(logrus.Fields{
		"SEID":  fmt.Sprintf("%016x", s.cp_seid),
		"state": s.state,
		"error": err,
	}).Debug("session error")
	if s.state != sessionStateFailed {
		s.state = sessionStateFailed
	}
	return err
}

func (s *pfcpSession) event(et sessionEventType, ev pfcpEvent) (*PFCPMeasurement, error) {
	oldState := s.state
	defer func() {
		if oldState == s.state {
			s.pc.log.WithFields(logrus.Fields{
				"SEID":     fmt.Sprintf("%016x", s.cp_seid),
				"oldState": oldState,
				"event":    et,
			}).Trace("session state machine event w/o transition")
		} else {
			s.pc.log.WithFields(logrus.Fields{
				"SEID":     fmt.Sprintf("%016x", s.cp_seid),
				"oldState": oldState,
				"event":    et,
				"newState": s.state,
			}).Trace("session state machine transition")
		}
	}()
	tk := sessionTransitionKey{state: s.state, event: et}
	tf, found := sessionTransitions[tk]
	if !found {
		return nil, s.error(errors.Errorf("Session %016x: can't handle event %s in state %s", s.cp_seid, et, s.state))
	}

	result, err := tf(s, ev)
	if err != nil {
		return nil, s.error(err)
	}

	return result, nil
}

func (s *pfcpSession) getMeasurement(m message.Message) (*PFCPMeasurement, error) {
	r, err := GetMeasurement(m)
	if err == nil && r != nil {
		for urrid, reports := range r.Reports {
			for _, report := range reports {
				s.pc.log.WithFields(logrus.Fields{
					"messageType": m.MessageTypeName(),
					"urrID":       urrid,
					"report":      report.String(),
				}).Trace("PFCP measurement")
			}
		}
	}
	return r, err
}

func getCauseIE(m message.Message) (causeIE, failedRuleIDIE *ie.IE, otherIEs []*ie.IE) {
	switch r := m.(type) {
	case *message.AssociationSetupResponse:
		return r.Cause, nil, r.IEs
	case *message.AssociationReleaseResponse:
		return r.Cause, nil, r.IEs
	case *message.AssociationUpdateResponse:
		return r.Cause, nil, r.IEs
	case *message.NodeReportResponse:
		return r.Cause, nil, r.IEs
	case *message.PFDManagementResponse:
		return r.Cause, nil, r.IEs
	case *message.SessionEstablishmentResponse:
		return r.Cause, r.FailedRuleID, r.IEs
	case *message.SessionDeletionResponse:
		return r.Cause, nil, r.IEs
	case *message.SessionModificationResponse:
		return r.Cause, r.FailedRuleID, r.IEs
	case *message.SessionReportResponse:
		return r.Cause, nil, r.IEs
	case *message.SessionSetDeletionResponse:
		return r.Cause, nil, r.IEs
	default:
		return nil, nil, nil
	}
}

const (
	TPErrorReportEnterpriseID = 0x48f9
	TPErrorReportIEID         = 0x8006
	TPErrorMessageIEID        = 0x8007
)

func parseTPErrorReport(ies []*ie.IE) (string, error) {
	for _, cur := range ies {
		if cur.EnterpriseID != TPErrorReportEnterpriseID || cur.Type != TPErrorReportIEID {
			continue
		}

		for len(cur.Payload) != 0 {
			var child ie.IE
			if err := child.UnmarshalBinary(cur.Payload); err != nil {
				return "", errors.Wrap(err, "error parsing child IE")
			}
			if child.EnterpriseID == TPErrorReportEnterpriseID || cur.Type == TPErrorMessageIEID {
				return string(child.Payload), nil
			}
		}
	}

	return "", nil
}

func verifyCause(m message.Message, seid SEID) error {
	causeIE, failedRuleIDIE, otherIEs := getCauseIE(m)
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

	if m.SEID() != 0 {
		seid = SEID(m.SEID())
	}

	var failedRuleID uint32
	if failedRuleIDIE != nil {
		failedRuleID, err = failedRuleIDIE.FailedRuleID()
		if err != nil {
			return errors.Wrap(err, "bad Failed Rule ID IE")
		}
	}

	msg, err := parseTPErrorReport(otherIEs)
	if err != nil {
		return errors.Wrap(err, "failed to find/parse error report")
	}
	return &PFCPServerError{Cause: cause, SEID: seid, FailedRuleID: failedRuleID, Message: msg}
}

func requestToEventType(m message.Message) (pfcpEventType, bool) {
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

func peerMessageToEventType(m message.Message) (pfcpEventType, bool) {
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
	case message.MsgTypeSessionReportRequest:
		return pfcpEventSessionReportRequest, true
	case message.MsgTypeHeartbeatRequest:
		return pfcpEventHeartbeatRequest, true
	default:
		return pfcpEventNone, false
	}
}

type pfcpRequest interface {
	SetSequenceNumber(seq uint32)
}

func GetMeasurement(m message.Message) (*PFCPMeasurement, error) {
	var urs []*ie.IE
	switch m.MessageType() {
	case message.MsgTypeSessionModificationResponse:
		urs = m.(*message.SessionModificationResponse).UsageReport
	case message.MsgTypeSessionDeletionResponse:
		urs = m.(*message.SessionDeletionResponse).UsageReport
	case message.MsgTypeSessionReportRequest:
		urs = m.(*message.SessionReportRequest).UsageReport
	default:
		panic("bad message type")
	}

	if len(urs) == 0 {
		return nil, nil
	}

	ms := PFCPMeasurement{
		Timestamp: time.Now(),
		Reports:   make(map[uint32][]PFCPReport),
	}

	for _, ur := range urs {
		r := PFCPReport{}

		urridIE, err := ur.FindByType(ie.URRID)
		if err != nil {
			return nil, errors.Wrap(err, "can't find URR ID IE")
		}

		urrid, err := urridIE.URRID()
		if err != nil {
			return nil, errors.Wrap(err, "can't parse URR ID IE")
		}

		startTime, err := ur.FindByType(ie.StartTime)
		if err != ie.ErrIENotFound {
			if err != nil {
				return nil, errors.Wrap(err, "can't find StartTime IE")
			}

			r.StartTime, err = startTime.StartTime()
			if err != nil {
				return nil, errors.Wrap(err, "can't parse StartTime IE")
			}
		}

		endTime, err := ur.FindByType(ie.EndTime)
		if err != ie.ErrIENotFound {
			if err != nil {
				return nil, errors.Wrap(err, "can't find EndTime IE")
			}

			r.EndTime, err = endTime.EndTime()
			if err != nil {
				return nil, errors.Wrap(err, "can't parse EndTime IE")
			}
		}

		volMeasurement, err := ur.FindByType(ie.VolumeMeasurement)
		if err != ie.ErrIENotFound {
			if err != nil {
				return nil, errors.Wrap(err, "can't find VolumeMeasurement IE")
			}

			parsedVolMeasurement, err := volMeasurement.VolumeMeasurement()
			if err != nil {
				return nil, errors.Wrap(err, "can't parse VolumeMeasurement IE")
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

			if parsedVolMeasurement.HasDLNOP() {
				r.DownlinkPacketCount = &parsedVolMeasurement.DownlinkNumberOfPackets
			}

			if parsedVolMeasurement.HasULNOP() {
				r.UplinkPacketCount = &parsedVolMeasurement.UplinkNumberOfPackets
			}

			if parsedVolMeasurement.HasTONOP() {
				r.TotalPacketCount = &parsedVolMeasurement.TotalNumberOfPackets
			}
		}

		durMeasurement, err := ur.FindByType(ie.DurationMeasurement)
		if err != ie.ErrIENotFound {
			if err != nil {
				return nil, errors.Wrap(err, "can't find DurationMeasurement IE")
			}

			duration, err := durMeasurement.DurationMeasurement()
			if err != nil {
				return nil, errors.Wrap(err, "can't parse DurationMeasurement IE")
			}

			r.Duration = &duration
		}

		ms.Reports[urrid] = append(ms.Reports[urrid], r)
	}

	return &ms, nil
}
