package pfcp

import (
	"testing"
	"time"
)

type testMsg struct {
	seq uint32
}

var _ queueEntry = &testMsg{}

func (m testMsg) Sequence() uint32 { return m.seq }

func sampleMsg(seq uint32) testMsg {
	return testMsg{seq: seq}
}

func TestRequestQueue(t *testing.T) {
	rq := newRequestQueue(time.Second)
	ms := []testMsg{
		sampleMsg(1),
		sampleMsg(2),
		sampleMsg(3),
	}
	now := time.Now()

	m, _ := rq.next()
	if m != nil {
		t.Error("queue not empty at the start")
	}

	for i := 0; i < 3; i++ {
		rq.add(ms[0], now.Add(10*time.Second), 100)

		nm, ts := rq.next()
		if nm != ms[0] {
			t.Error("bad next")
		}
		if ts != now.Add(11*time.Second) {
			t.Error("bad ts")
		}

		rq.add(ms[1], now.Add(5*time.Second), 100)
		nm, ts = rq.next()
		if nm != ms[1] {
			t.Error("bad next")
		}
		if ts != now.Add(6*time.Second) {
			t.Error("bad ts")
		}

		rq.add(ms[2], now.Add(7*time.Second), 100)
		nm, ts = rq.next()
		if nm != ms[1] {
			t.Error("bad next")
		}
		if ts != now.Add(6*time.Second) {
			t.Error("bad ts")
		}

		rq.reschedule(ms[1], now.Add(20*time.Second))

		nm, ts = rq.next()
		if nm != ms[2] {
			t.Error("bad next")
		}
		if ts != now.Add(8*time.Second) {
			t.Error("bad ts")
		}

		// sampleMsg(3) has the same seq as ms[2]
		if *rq.remove(sampleMsg(3)) != ms[2] {
			t.Error("remove returned wrong value")
		}
		nm, ts = rq.next()
		if nm != ms[0] {
			t.Error("bad next")
		}
		if ts != now.Add(11*time.Second) {
			t.Error("bad ts")
		}

		if *rq.remove(ms[0]) != ms[0] {
			t.Error("remove returned wrong value")
		}
		if rq.remove(ms[0]) != nil {
			t.Error("duplicate remove returned non-nil")
		}
		nm, ts = rq.next()
		if nm != ms[1] {
			t.Error("bad next")
		}
		if ts != now.Add(21*time.Second) {
			t.Error("bad ts")
		}

		if *rq.remove(ms[1]) != ms[1] {
			t.Error("remove returned wrong value")
		}
		m, _ := rq.next()
		if m != nil {
			t.Error("queue not empty at the end")
		}

		if rq.remove(ms[1]) != nil {
			t.Error("duplicate remove returned non-nil")
		}
	}

	rq.add(ms[0], now.Add(10*time.Second), 100)
	rq.clear()

	m, _ = rq.next()
	if m != nil {
		t.Error("queue not empty after clear")
	}
	if rq.remove(ms[0]) != nil {
		t.Error("remove returned non-nil after clear")
	}
}
