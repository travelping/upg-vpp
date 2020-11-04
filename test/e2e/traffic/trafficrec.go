package traffic

import (
	"fmt"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

const (
	MAX_ERRORS = 16
)

// SimpleTrafficRec records stats and errors, but only verifies there
// are no errors
type SimpleTrafficRec struct {
	sync.Mutex
	errors []string
	stats  TrafficStats
}

var _ TrafficRec = &SimpleTrafficRec{}

func (tr *SimpleTrafficRec) recordErrorUnlocked(format string, args ...interface{}) {
	if len(tr.errors) < MAX_ERRORS {
		tr.errors = append(tr.errors, fmt.Sprintf(format, args...))
	}
}

func (tr *SimpleTrafficRec) RecordError(format string, args ...interface{}) {
	tr.Lock()
	defer tr.Unlock()
	tr.recordErrorUnlocked(format, args...)
}

func (tr *SimpleTrafficRec) RecordStats(stats TrafficStats) {
	tr.Lock()
	defer tr.Unlock()
	tr.stats.ClientSent += stats.ClientSent
	tr.stats.ClientReceived += stats.ClientReceived
	tr.stats.ServerSent += stats.ServerSent
	tr.stats.ServerReceived += stats.ServerReceived
}

func (tr *SimpleTrafficRec) verifyUnlocked() error {
	if len(tr.errors) == 0 {
		return nil
	}
	return errors.Errorf("errors detected:\n%s\n", strings.Join(tr.errors, "\n"))
}

func (tr *SimpleTrafficRec) Verify() error {
	tr.Lock()
	defer tr.Unlock()
	return tr.verifyUnlocked()
}

func (tr *SimpleTrafficRec) Stats() TrafficStats {
	tr.Lock()
	defer tr.Unlock()
	return tr.stats
}

// PreciseTrafficrec records stats and errors and verifies both
type PreciseTrafficRec struct {
	SimpleTrafficRec
}

var _ TrafficRec = &PreciseTrafficRec{}

func (tr *PreciseTrafficRec) Verify() error {
	tr.Lock()
	defer tr.Unlock()

	if tr.stats.ClientSent != tr.stats.ServerReceived {
		tr.recordErrorUnlocked("the client sent %d bytes, but the server received %d",
			tr.stats.ClientSent, tr.stats.ServerReceived)
	}

	if tr.stats.ServerSent != tr.stats.ClientReceived {
		tr.recordErrorUnlocked("the server sent %d bytes, but the client received %d",
			tr.stats.ServerSent, tr.stats.ClientReceived)
	}

	return tr.verifyUnlocked()
}
