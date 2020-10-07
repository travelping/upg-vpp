package framework

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const (
	PFCP_BUF_SIZE = 100000
	PFCP_PORT     = 8805

	ApplyAction_FORW = 2
	UEIPAddress_SD   = 4
	UEIPAddress_V4   = 2
	UEIPAddress_V6   = 1
)

var (
	errUnexpected = errors.New("unexpected pfcp message")
	errTimeout    = errors.New("timed out")
	errDone       = errors.New("pfcp loop complete")
)

type pfcpState interface {
	Name() string
	Enter(pc *PFCPConnection) error
	HandleTimeout(pc *PFCPConnection) error
	HandleBegin(pc *PFCPConnection)
	HandleStop(pc *PFCPConnection)
	HandleAssociationSetupResponse(pc *PFCPConnection, asr *message.AssociationSetupResponse) error
	HandleHeartbeatRequest(pc *PFCPConnection, hb *message.HeartbeatRequest) error
	HandleSessionEstablishmentResponse(pc *PFCPConnection, ser *message.SessionEstablishmentResponse) error
	HandleSessionModificationResponse(pc *PFCPConnection, smr *message.SessionModificationResponse) error
}

type PFCPConfig struct {
	Namespace *NetNS
	UNodeIP   net.IP
	// TODO: UEIP should be per-session
	UEIP                net.IP
	NodeID              string
	RequestTimeout      time.Duration
	ReportQueryInterval time.Duration
}

func (cfg *PFCPConfig) setDefaults() {
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 3 * time.Second
	}
}

type PFCPConnection struct {
	cfg            PFCPConfig
	conn           *net.UDPConn
	seq            uint32
	state          pfcpState
	timestamp      time.Time
	pendingEnter   bool
	timer          *time.Timer
	messageCh      chan message.Message
	listenErrCh    chan error
	done           bool
	sessionStartCh chan struct{}
	stopCh         chan struct{}
	Stopped        bool
	curSEID        uint64
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

func (pc *PFCPConnection) SetState(newState pfcpState) {
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

func (pc *PFCPConnection) Run() error {
	var err error
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
	pc.SetState(&pfcpInitialState{})
	pc.state.HandleBegin(pc)

LOOP:
	for !pc.done {
		if pc.pendingEnter {
			pc.pendingEnter = false
			fmt.Printf("* Enter state: %s\n", pc.state.Name())
			if err = pc.state.Enter(pc); err != nil {
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
			if err = pc.state.HandleTimeout(pc); err != nil {
				err = errors.Wrapf(err, "timeout in state %s", pc.state.Name())
				break LOOP
			}
		case <-pc.stopCh:
			pc.state.HandleStop(pc)
		case err = <-pc.listenErrCh:
			fmt.Printf("* Listener error: %v\n", err)
			break LOOP
		}
	}

	return err
}

func (pc *PFCPConnection) Done() {
	pc.done = true
}

func (pc *PFCPConnection) Start() (chan struct{}, chan error) {
	pc.Stopped = false
	pc.stopCh = make(chan struct{})
	pc.sessionStartCh = make(chan struct{})
	errCh := make(chan error)
	go func() {
		errCh <- pc.Run()
	}()
	return pc.sessionStartCh, errCh
}

func (pc *PFCPConnection) Stop() {
	if pc.Stopped {
		return
	}
	if pc.stopCh == nil {
		panic("Start() not called")
	}
	close(pc.stopCh)
	pc.Stopped = true
}

func (pc *PFCPConnection) handleMessage(msg message.Message) error {
	switch msg.MessageType() {
	case message.MsgTypeAssociationSetupResponse:
		return pc.state.HandleAssociationSetupResponse(pc, msg.(*message.AssociationSetupResponse))
	case message.MsgTypeHeartbeatRequest:
		return pc.state.HandleHeartbeatRequest(pc, msg.(*message.HeartbeatRequest))
	case message.MsgTypeSessionEstablishmentResponse:
		return pc.state.HandleSessionEstablishmentResponse(pc, msg.(*message.SessionEstablishmentResponse))
	case message.MsgTypeSessionModificationResponse:
		return pc.state.HandleSessionModificationResponse(pc, msg.(*message.SessionModificationResponse))
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

func (pc *PFCPConnection) verifySequence(m message.Message) bool {
	if m.Sequence() != pc.seq {
		fmt.Printf("* WARNING: skipping %s with wrong seq (%d instead of %d)\n",
			m.MessageTypeName(), m.Sequence(), pc.seq)
		return false
	}
	return true
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

func verifyCause(causeIE *ie.IE) error {
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

type pfcpStateBase struct{}

func (s *pfcpStateBase) Enter(pc *PFCPConnection) error         { return nil }
func (s *pfcpStateBase) HandleTimeout(pc *PFCPConnection) error { return errTimeout }
func (s *pfcpStateBase) HandleBegin(pc *PFCPConnection)         {}
func (s *pfcpStateBase) HandleStop(pc *PFCPConnection) {
	pc.Done()
}

func (s *pfcpStateBase) HandleAssociationSetupResponse(pc *PFCPConnection, asr *message.AssociationSetupResponse) error {
	return errUnexpected
}

func (s *pfcpStateBase) HandleHeartbeatRequest(pc *PFCPConnection, hr *message.HeartbeatRequest) error {
	fmt.Printf("* Heartbeat request\n")
	return pc.Send(message.NewHeartbeatResponse(hr.SequenceNumber, ie.NewRecoveryTimeStamp(pc.timestamp)))
}

func (s *pfcpStateBase) HandleSessionEstablishmentResponse(pc *PFCPConnection, ser *message.SessionEstablishmentResponse) error {
	return errUnexpected
}

func (s *pfcpStateBase) HandleSessionModificationResponse(pc *PFCPConnection, smr *message.SessionModificationResponse) error {
	return errUnexpected
}

type pfcpInitialState struct{ pfcpStateBase }

var _ pfcpState = &pfcpInitialState{}

func (s *pfcpInitialState) Name() string { return "INITIAL" }

func (s *pfcpInitialState) HandleBegin(pc *PFCPConnection) {
	pc.SetState(&pfcpAssociatingState{})
}

type pfcpAssociatingState struct{ pfcpStateBase }

var _ pfcpState = &pfcpAssociatingState{}

func (s *pfcpAssociatingState) Name() string { return "ASSOCIATING" }

func (s *pfcpAssociatingState) Enter(pc *PFCPConnection) error {
	pc.SetTimeout(pc.cfg.RequestTimeout)
	return pc.Send(message.NewAssociationSetupRequest(
		pc.seq,
		ie.NewRecoveryTimeStamp(pc.timestamp),
		ie.NewNodeID("", "", pc.cfg.NodeID)))
}

func (s *pfcpAssociatingState) HandleTimeout(pc *PFCPConnection) error {
	pc.Reenter()
	return nil
}

func (s *pfcpAssociatingState) HandleAssociationSetupResponse(pc *PFCPConnection, asr *message.AssociationSetupResponse) error {
	if !pc.verifySequence(asr) {
		return nil
	}
	pc.IncSeq()
	if err := verifyCause(asr.Cause); err != nil {
		return errors.Wrap(err, "AssociationSetupResponse")
	}
	pc.SetState(&pfcpAssociatedState{})
	return nil
}

type pfcpAssociatedState struct{ pfcpStateBase }

var _ pfcpState = &pfcpAssociatedState{}

func (s *pfcpAssociatedState) Name() string { return "ASSOCIATED" }

func (s *pfcpAssociatedState) Enter(pc *PFCPConnection) error {
	pc.SetTimeout(pc.cfg.RequestTimeout)
	for pc.curSEID == 0 {
		pc.curSEID = rand.Uint64()
	}

	return pc.Send(message.NewSessionEstablishmentRequest(
		0, 0, 0, pc.seq, 0,
		ie.NewCreateFAR(
			ie.NewApplyAction(ApplyAction_FORW),
			ie.NewFARID(1),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
				ie.NewNetworkInstance(EncodeAPN("sgi")))),
		// TODO: replace for PGW (reverseFAR)
		ie.NewCreateFAR(
			ie.NewApplyAction(ApplyAction_FORW),
			ie.NewFARID(2),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewNetworkInstance(EncodeAPN("access")))),
		ie.NewCreateURR(
			ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
			ie.NewReportingTriggers(0),
			ie.NewURRID(1)),
		ie.NewCreateURR(
			ie.NewMeasurementMethod(0, 1, 1), // VOLUM=1 DURAT=1
			ie.NewReportingTriggers(0),
			ie.NewURRID(2)),
		// TODO: replace for PGW (forwardPDR)
		ie.NewCreatePDR(
			ie.NewFARID(1),
			ie.NewPDI(
				ie.NewNetworkInstance(EncodeAPN("access")),
				ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0),
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				// TODO: replace for IPv6
				ie.NewUEIPAddress(UEIPAddress_V4, pc.cfg.UEIP.String(), "", 0)),
			ie.NewPDRID(1),
			ie.NewPrecedence(200),
			ie.NewURRID(1),
		),
		ie.NewCreatePDR(
			ie.NewFARID(2),
			ie.NewPDI(
				ie.NewNetworkInstance(EncodeAPN("sgi")),
				ie.NewSDFFilter("permit out ip from any to assigned", "", "", "", 0),
				ie.NewSourceInterface(ie.SrcInterfaceSGiLANN6LAN),
				// TODO: replace for IPv6
				ie.NewUEIPAddress(UEIPAddress_V4|UEIPAddress_SD, pc.cfg.UEIP.String(), "", 0)),
			ie.NewPDRID(2),
			ie.NewPrecedence(200),
			ie.NewURRID(1),
		),
		// TODO: replace for IPv6
		ie.NewFSEID(pc.curSEID, pc.cfg.Namespace.IPNet.IP, nil, nil),
		ie.NewNodeID("", "", pc.cfg.NodeID),
	))
}

func (s *pfcpAssociatedState) HandleSessionEstablishmentResponse(pc *PFCPConnection, ser *message.SessionEstablishmentResponse) error {
	if !pc.verifySequence(ser) {
		return nil
	}
	pc.IncSeq()
	if err := verifyCause(ser.Cause); err != nil {
		return errors.Wrap(err, "SessionEstablishmentResponse")
	}
	pc.SetState(&pfcpSessionEstablishedState{})
	return nil
}

type pfcpSessionEstablishedState struct{ pfcpStateBase }

var _ pfcpState = &pfcpSessionEstablishedState{}

func (s *pfcpSessionEstablishedState) Name() string { return "SESSION_ESTABLISHED" }

func (s *pfcpSessionEstablishedState) Enter(pc *PFCPConnection) error {
	if pc.sessionStartCh != nil {
		close(pc.sessionStartCh)
	}
	if pc.cfg.ReportQueryInterval > 0 {
		pc.SetTimeout(pc.cfg.ReportQueryInterval)
	}
	return nil
}

func (s *pfcpSessionEstablishedState) HandleTimeout(pc *PFCPConnection) error {
	pc.SetTimeout(pc.cfg.ReportQueryInterval)
	// FIXME: use another ID for app detection
	return pc.Send(message.NewSessionModificationRequest(
		0, 0, pc.curSEID, pc.seq, 0,
		ie.NewQueryURR(ie.NewURRID(1))))
}

func (s *pfcpSessionEstablishedState) HandleSessionModificationResponse(pc *PFCPConnection, smr *message.SessionModificationResponse) error {
	if !pc.verifySequence(smr) {
		return nil
	}
	pc.IncSeq()
	if err := verifyCause(smr.Cause); err != nil {
		return errors.Wrap(err, "SessionModificationResponse")
	}
	if len(smr.UsageReport) != 1 {
		return errors.Errorf("expected 1 UsageReport in SessionModificationResponse, got %d", len(smr.UsageReport))
	}

	volMeasurement, err := smr.UsageReport[0].FindByType(ie.VolumeMeasurement)
	if err != nil {
		return errors.Wrap(err, "can't find VolumeMeasurement IE")
	}

	parsedVolMeasurement, err := volMeasurement.VolumeMeasurement()
	if err != nil {
		return errors.Wrap(err, "can't parse VolumeMeasurement IE")
	}

	if !parsedVolMeasurement.HasDLVOL() {
		return errors.New("no DLVOL in VolumeMeasurement")
	}

	if !parsedVolMeasurement.HasULVOL() {
		return errors.New("no ULVOL in VolumeMeasurement")
	}

	if !parsedVolMeasurement.HasTOVOL() {
		return errors.New("no TOVOL in VolumeMeasurement")
	}

	durMeasurement, err := smr.UsageReport[0].FindByType(ie.DurationMeasurement)
	if err != nil {
		return errors.Wrap(err, "can't find DurationMeasurement IE")
	}

	duration, err := durMeasurement.DurationMeasurement()
	if err != nil {
		return errors.Wrap(err, "can't parse DurationMeasurement IE")
	}

	fmt.Printf("* SessionModificationResponse: up = %d, down = %d, tot = %d, duration = %v\n",
		parsedVolMeasurement.UplinkVolume, parsedVolMeasurement.DownlinkVolume, parsedVolMeasurement.TotalVolume, duration)

	return nil
}

// TODO: own logging func
// TODO: close the session
// TODO: release association
// TODO: command channel:
//       * add session
//       * close session
//       * modify session (just for report initially)
//       * done
