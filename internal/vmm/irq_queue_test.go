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

	// Producers must remain free to enqueue and kick vCPUs while an older
	// Hypervisor.framework injection is in progress.
	queuedNewer := make(chan struct{}, 1)
	go func() {
		queue.push(irqChange{irq: 73, level: false})
		queuedNewer <- struct{}{}
	}()
	select {
	case <-queuedNewer:
	case <-time.After(2 * time.Second):
		t.Fatal("IRQ producer blocked behind an in-progress injection")
	}

	secondDone := make(chan error, 1)
	go func() { secondDone <- queue.apply(apply) }()
	select {
	case err := <-secondDone:
		t.Fatalf("newer IRQ batch bypassed an in-progress batch: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
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
