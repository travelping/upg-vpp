// request_queue_test.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/message"
)

func sampleMsg(seq uint32) message.Message {
	return message.NewSessionEstablishmentRequest(0, 0, 0, seq, 0)
}

func TestRequestQueue(t *testing.T) {
	rq := newRequestQueue(time.Second)
	ms := []message.Message{
		sampleMsg(1),
		sampleMsg(2),
		sampleMsg(3),
	}
	now := time.Now()

	if m, _ := rq.next(); m != nil {
		t.Error("queue not empty at the start")
	}

	for i := 0; i < 3; i++ {
		rq.add(ms[0], now.Add(10*time.Second))

		nm, ts := rq.next()
		if nm != ms[0] {
			t.Error("bad next")
		}
		if ts != now.Add(11*time.Second) {
			t.Error("bad ts")
		}

		rq.add(ms[1], now.Add(5*time.Second))
		nm, ts = rq.next()
		if nm != ms[1] {
			t.Error("bad next")
		}
		if ts != now.Add(6*time.Second) {
			t.Error("bad ts")
		}

		rq.add(ms[2], now.Add(7*time.Second))
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

		if !rq.remove(ms[2]) {
			t.Error("remove returned false")
		}
		nm, ts = rq.next()
		if nm != ms[0] {
			t.Error("bad next")
		}
		if ts != now.Add(11*time.Second) {
			t.Error("bad ts")
		}

		if !rq.remove(ms[0]) {
			t.Error("remove returned false")
		}
		if rq.remove(ms[0]) {
			t.Error("duplicate remove returned true")
		}
		nm, ts = rq.next()
		if nm != ms[1] {
			t.Error("bad next")
		}
		if ts != now.Add(21*time.Second) {
			t.Error("bad ts")
		}

		if !rq.remove(ms[1]) {
			t.Error("remove returned false")
		}
		if m, _ := rq.next(); m != nil {
			t.Error("queue not empty at the end")
		}

		if rq.remove(ms[1]) {
			t.Error("duplicate remove returned true")
		}
	}

	rq.add(ms[0], now.Add(10*time.Second))
	rq.clear()
	if m, _ := rq.next(); m != nil {
		t.Error("queue not empty after clear")
	}
	if rq.remove(ms[0]) {
		t.Error("remove succeeded after clear")
	}
}
