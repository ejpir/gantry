package netpol

import (
	"sync"
	"time"
)

const trafficFlushInterval = time.Second

// trafficPublisher solely owns the periodic writer lifecycle. Close is a
// joined transition: one caller stops the goroutine and every caller waits for
// the same final flush to complete.
type trafficPublisher struct {
	flush     func()
	interval  time.Duration
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func startTrafficPublisher(persistence *trafficPersistence) *trafficPublisher {
	if persistence == nil {
		return newTrafficPublisher(0, nil)
	}
	return newTrafficPublisher(trafficFlushInterval, persistence.flush)
}

func newTrafficPublisher(interval time.Duration, flush func()) *trafficPublisher {
	publisher := &trafficPublisher{
		flush:    flush,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if flush == nil {
		close(publisher.done)
		return publisher
	}
	go publisher.run()
	return publisher
}

func (p *trafficPublisher) run() {
	ticker := time.NewTicker(p.interval)
	defer func() {
		ticker.Stop()
		p.flush()
		close(p.done)
	}()
	for {
		select {
		case <-ticker.C:
			p.flush()
		case <-p.stop:
			return
		}
	}
}

func (p *trafficPublisher) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() { close(p.stop) })
	<-p.done
}
