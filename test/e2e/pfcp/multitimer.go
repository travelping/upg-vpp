package pfcp

import (
	"sync"
	"time"
)

type MultiTimer struct {
	timers     map[int]*time.Timer
	channel    chan int
	channelMtx sync.Mutex
	timersMtx  sync.Mutex
}

func (mt *MultiTimer) StartTimer(id int, duration time.Duration) {
	mt.timersMtx.Lock()
	defer mt.timersMtx.Unlock()

	if mt.timers == nil {
		mt.timers = make(map[int]*time.Timer)
	}

	if timer, ok := mt.timers[id]; ok {
		timer.Stop()
	}

	timer := time.AfterFunc(duration, func() {
		mt.Channel() <- id
		mt.timersMtx.Lock()
		defer mt.timersMtx.Unlock()
		delete(mt.timers, id)
	})
	mt.timers[id] = timer
}

func (mt *MultiTimer) StopTimer(id int) {
	mt.timersMtx.Lock()
	defer mt.timersMtx.Unlock()

	if timer, ok := mt.timers[id]; ok {
		timer.Stop()
		delete(mt.timers, id)
	}
}

func (mt *MultiTimer) Channel() chan int {
	mt.channelMtx.Lock()
	defer mt.channelMtx.Unlock()

	if mt.channel == nil {
		mt.channel = make(chan int)
	}

	return mt.channel
}
