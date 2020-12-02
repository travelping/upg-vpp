package pfcp

import (
	"container/heap"
	"time"

	"github.com/wmnsk/go-pfcp/message"
)

type pendingRequest struct {
	msg         message.Message
	nextAttempt time.Time
	index       int
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

func (rq *requestQueue) add(m message.Message, now time.Time) {
	r := &pendingRequest{
		msg:         m,
		nextAttempt: now.Add(rq.timeout),
	}
	rq.bySeq[m.Sequence()] = r
	heap.Push(rq, r)
}

func (rq *requestQueue) remove(m message.Message) bool {
	seq := m.Sequence()
	r, found := rq.bySeq[seq]
	if !found {
		return false
	}
	heap.Remove(rq, r.index)
	delete(rq.bySeq, seq)
	return true
}

func (rq *requestQueue) reschedule(m message.Message, now time.Time) {
	r, found := rq.bySeq[m.Sequence()]
	if !found {
		return
	}
	r.nextAttempt = now.Add(rq.timeout)
	heap.Fix(rq, r.index)
}

func (rq *requestQueue) next() (message.Message, time.Time) {
	if rq.Len() == 0 {
		return nil, time.Time{}
	}
	return rq.rs[0].msg, rq.rs[0].nextAttempt
}

func (rq *requestQueue) clear() {
	rq.bySeq = make(map[uint32]*pendingRequest)
	rq.rs = nil
}
