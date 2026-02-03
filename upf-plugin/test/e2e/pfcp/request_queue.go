// request_queue.go - 3GPP TS 29.244 GTP-U UP plug-in
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
	"container/heap"
	"time"

	"github.com/pkg/errors"
)

var NoMoreRetransmitsErr = errors.New("max number of retransmits reached")

type queueEntry interface {
	Sequence() uint32
}

type pendingRequest struct {
	entry        queueEntry
	nextAttempt  time.Time
	index        int
	attemptsLeft int
}

type requestQueue struct {
	timeout time.Duration
	rs      []*pendingRequest
	bySeq   map[uint32]*pendingRequest
}

func newRequestQueue(timeout time.Duration) *requestQueue {
	return &requestQueue{
		timeout: timeout,
		bySeq:   make(map[uint32]*pendingRequest),
	}
}

func (rq *requestQueue) Len() int { return len(rq.rs) }

func (rq *requestQueue) Less(i, j int) bool {
	return rq.rs[i].nextAttempt.Before(rq.rs[j].nextAttempt)
}

func (rq *requestQueue) Swap(i, j int) {
	rq.rs[i], rq.rs[j] = rq.rs[j], rq.rs[i]
	rq.rs[i].index = i
	rq.rs[j].index = j
}

func (rq *requestQueue) Push(x interface{}) {
	n := len(rq.rs)
	item := x.(*pendingRequest)
	item.index = n
	rq.rs = append(rq.rs, item)
}

func (rq *requestQueue) Pop() interface{} {
	old := rq.rs
	n := len(old)
	r := old[n-1]
	old[n-1] = nil
	r.index = -1
	rq.rs = old[0 : n-1]
	return r
}

func (rq *requestQueue) add(e queueEntry, now time.Time, maxAttempts int) {
	if e.Sequence() == 0 {
		panic("can't add an entry with zero sequence number")
	}
	if maxAttempts <= 0 {
		panic("N of attempts must be > 0")
	}
	r := &pendingRequest{
		entry:        e,
		nextAttempt:  now.Add(rq.timeout),
		attemptsLeft: maxAttempts - 1,
	}
	rq.bySeq[e.Sequence()] = r
	heap.Push(rq, r)
}

func (rq *requestQueue) remove(e queueEntry) *queueEntry {
	seq := e.Sequence()
	r, found := rq.bySeq[seq]
	if !found {
		return nil
	}
	heap.Remove(rq, r.index)
	delete(rq.bySeq, seq)
	return &r.entry
}

func (rq *requestQueue) reschedule(e queueEntry, now time.Time) {
	r, found := rq.bySeq[e.Sequence()]
	if !found {
		panic("rescheduling non-existent message")
	}
	r.nextAttempt = now.Add(rq.timeout)
	heap.Fix(rq, r.index)
}

func (rq *requestQueue) next() (queueEntry, time.Time) {
	if rq.Len() == 0 {
		if len(rq.bySeq) != 0 {
			panic("bySeq not empty")
		}
		return nil, time.Time{}
	}
	if rq.rs[0].entry == nil {
		panic("null entry")
	}
	return rq.rs[0].entry, rq.rs[0].nextAttempt
}

func (rq *requestQueue) clear() {
	rq.bySeq = make(map[uint32]*pendingRequest)
	rq.rs = nil
}
