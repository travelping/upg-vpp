package framework

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const (
	PFCP_BUF_SIZE = 100000
	PFCP_PORT     = 8805
)

var (
	errUnexpected = errors.New("unexpected pfcp message")
	errTimeout    = errors.New("timed out")
	errDone       = errors.New("pfcp loop complete")
)

type pfcpState interface {
	Name() string
	Enter() error
	Timeout() error
	HandleBegin()
	HandleStop()
	HandleAssociationSetupResponse(asr *message.AssociationSetupResponse) error
	HandleHeartbeatRequest(hb *message.HeartbeatRequest) error
	HandleSessionEstablishmentResponse(ser *message.SessionEstablishmentResponse) error
}

type PFCPConfig struct {
	Namespace          *NetNS
	UNodeIP            net.IP
	NodeID             string
	AssociationTimeout time.Duration
}

func (cfg *PFCPConfig) setDefaults() {
	if cfg.AssociationTimeout == 0 {
		cfg.AssociationTimeout = 3 * time.Second
	}
}

type PFCPConnection struct {
	cfg          PFCPConfig
	conn         *net.UDPConn
	seq          uint32
	state        pfcpState
	timestamp    time.Time
	pendingEnter bool
	timer        *time.Timer
	messageCh    chan message.Message
	listenErrCh  chan error
	done         bool
}

func NewPFCPConnection(cfg PFCPConfig) *PFCPConnection {
	cfg.setDefaults()
	return &PFCPConnection{
		cfg: cfg,
	}
}

func (pc *PFCPConnection) enterState() {
	if pc.timer != nil {
		pc.timer.Stop()
		pc.timer = nil
	}
	pc.pendingEnter = true
}

func (pc *PFCPConnection) SetState(stateFunc func(*PFCPConnection) pfcpState) {
	newState := stateFunc(pc)
	if pc.state != nil {
		fmt.Printf("*** %s -> %s\n", pc.state.Name(), newState.Name())
	}
	pc.state = newState
	pc.enterState()
}

func (pc *PFCPConnection) Reenter() {
	pc.enterState()
}

func (pc *PFCPConnection) SetTimeout(d time.Duration) {
	if pc.timer != nil {
		pc.timer.Stop()
	}
	// create a new timer so there's no need to drain its channel
	// before Reset()
	pc.timer = time.NewTimer(d)
}

func (pc *PFCPConnection) IncSeq() {
	pc.seq++
}

func (pc *PFCPConnection) RunFor(d time.Duration) error {
	var err error
	var stopCh <-chan time.Time
	if d != 0 {
		stopCh = time.After(d)
	}
	pc.conn = nil
	pc.messageCh = make(chan message.Message, 1)
	pc.listenErrCh = make(chan error, 1)
	pc.timestamp = time.Now()
	pc.seq = 1

	if err = pc.dial(); err != nil {
		return err
	}
	defer pc.close()

	pc.done = false
	pc.SetState(newPFCPInitialState)
	pc.state.HandleBegin()

LOOP:
	for !pc.done {
		if pc.pendingEnter {
			pc.pendingEnter = false
			fmt.Printf("* Enter state: %s\n", pc.state.Name())
			if err = pc.state.Enter(); err != nil {
				err = errors.Wrapf(err, "Enter %s", pc.state.Name())
				break LOOP
			}
		}
		var timerCh <-chan time.Time
		if pc.timer != nil {
			timerCh = pc.timer.C
		}

		select {
		case msg := <-pc.messageCh:
			if err = pc.handleMessage(msg); err != nil {
				err = errors.Wrapf(err, "error handling %s in state %s", msg.MessageTypeName(), pc.state.Name())
				break LOOP
			}
		case <-timerCh:
			if err = pc.state.Timeout(); err != nil {
				err = errors.Wrapf(err, "timeout in state %s", pc.state.Name())
				break LOOP
			}
		case <-stopCh:
			pc.state.HandleStop()
		case err = <-pc.listenErrCh:
			fmt.Printf("* Listener error: %v\n", err)
			break LOOP
		}
	}

	return err
}

func (pc *PFCPConnection) Run() error {
	return pc.RunFor(0)
}

func (pc *PFCPConnection) Done() {
	pc.done = true
}

func (pc *PFCPConnection) handleMessage(msg message.Message) error {
	switch msg.MessageType() {
	case message.MsgTypeAssociationSetupResponse:
		return pc.state.HandleAssociationSetupResponse(msg.(*message.AssociationSetupResponse))
	case message.MsgTypeHeartbeatRequest:
		return pc.state.HandleHeartbeatRequest(msg.(*message.HeartbeatRequest))
	case message.MsgTypeSessionEstablishmentResponse:
		return pc.state.HandleSessionEstablishmentResponse(msg.(*message.SessionEstablishmentResponse))
	default:
		return errors.Errorf("can't handle message type %s", msg.MessageTypeName())
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

func (pc *PFCPConnection) Send(m message.Message) error {
	bs := make([]byte, m.MarshalLen())
	if err := m.MarshalTo(bs); err != nil {
		return errors.Wrap(err, "marshal pfcp message")
	}

	if _, err := pc.conn.Write(bs); err != nil {
		return errors.Wrap(err, "send pfcp message")
	}

	return nil
}

type pfcpStateBase struct {
	*PFCPConnection
}

func (b *pfcpStateBase) Timeout() error { return errTimeout }
func (b *pfcpStateBase) Enter() error   { return nil }
func (b *pfcpStateBase) HandleBegin()   {}
func (b *pfcpStateBase) HandleStop() {
	b.Done()
}

func (b *pfcpStateBase) HandleAssociationSetupResponse(asr *message.AssociationSetupResponse) error {
	return errUnexpected
}

func (b *pfcpStateBase) HandleHeartbeatRequest(hb *message.HeartbeatRequest) error {
	return errUnexpected
}

func (b *pfcpStateBase) HandleSessionEstablishmentResponse(ser *message.SessionEstablishmentResponse) error {
	return errUnexpected
}

type pfcpInitialState struct {
	*pfcpStateBase
}

func newPFCPInitialState(pc *PFCPConnection) pfcpState {
	return &pfcpInitialState{
		pfcpStateBase: &pfcpStateBase{
			PFCPConnection: pc,
		},
	}
}

func (s *pfcpInitialState) Name() string { return "INITIAL" }

func (s *pfcpInitialState) HandleBegin() {
	s.SetState(newPFCPAssociatingState)
}

type pfcpAssociatingState struct {
	*pfcpStateBase
}

func newPFCPAssociatingState(pc *PFCPConnection) pfcpState {
	return &pfcpAssociatingState{
		pfcpStateBase: &pfcpStateBase{
			PFCPConnection: pc,
		},
	}
}

func (s *pfcpAssociatingState) Name() string { return "ASSOCIATING" }

func (s *pfcpAssociatingState) Enter() error {
	s.SetTimeout(s.cfg.AssociationTimeout)
	return s.Send(message.NewAssociationSetupRequest(
		s.seq,
		ie.NewRecoveryTimeStamp(s.timestamp),
		ie.NewNodeID("", "", s.cfg.NodeID)))
}

func (s *pfcpAssociatingState) HandleTimeout() {
	s.Reenter()
}

func (s *pfcpAssociatingState) HandleAssociationSetupResponse(asr *message.AssociationSetupResponse) error {
	s.IncSeq()
	s.SetState(newPFCPAssociatedState)
	return nil
}

type pfcpAssociatedState struct {
	*pfcpStateBase
}

func newPFCPAssociatedState(pc *PFCPConnection) pfcpState {
	return &pfcpAssociatedState{
		pfcpStateBase: &pfcpStateBase{
			PFCPConnection: pc,
		},
	}
}

func (s *pfcpAssociatedState) Name() string { return "ASSOCIATED" }

func (s *pfcpAssociatedState) HandleHeartbeatRequest(hr *message.HeartbeatRequest) error {
	fmt.Printf("* Heartbeat request\n")
	err := s.Send(message.NewHeartbeatResponse(hr.SequenceNumber, ie.NewRecoveryTimeStamp(s.timestamp)))
	return err
}

// TODO: own logging func
// TODO: examine AssociationSetupResponse
// TODO: release association
// TODO: command channel:
//       * add session
//       * close session
//       * modify session (just for report initially)
//       * done
