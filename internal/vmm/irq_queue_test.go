package vmm

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestSerializedIRQQueueDoesNotReorderConcurrentBatches(t *testing.T) {
	var queue serializedIRQQueue
	queue.push(irqChange{irq: 73, level: true})

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var appliedMu sync.Mutex
	var applied []irqChange
	apply := func(irq int, level bool) error {
		change := irqChange{irq: irq, level: level}
		appliedMu.Lock()
		applied = append(applied, change)
		first := len(applied) == 1
		appliedMu.Unlock()
		if first {
			close(firstEntered)
			<-releaseFirst
		}
		return nil
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- queue.apply(apply) }()
	<-firstEntered

	queuedNewer := make(chan struct{})
	go func() {
		queue.push(irqChange{irq: 73, level: false})
		close(queuedNewer)
	}()
	select {
	case <-queuedNewer:
		t.Fatal("newer IRQ change bypassed an in-progress batch")
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	<-queuedNewer
	if err := queue.apply(apply); err != nil {
		t.Fatal(err)
	}

	want := []irqChange{{irq: 73, level: true}, {irq: 73, level: false}}
	if !reflect.DeepEqual(applied, want) {
		t.Fatalf("applied IRQ changes = %+v, want %+v", applied, want)
	}
}

func TestSerializedIRQQueueReportsSetterFailure(t *testing.T) {
	var queue serializedIRQQueue
	queue.push(irqChange{irq: 73, level: true})
	want := errors.New("set SPI failed")
	err := queue.apply(func(int, bool) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("apply error = %v, want %v", err, want)
	}
}
