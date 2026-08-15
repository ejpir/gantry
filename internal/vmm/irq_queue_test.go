package vmm

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestSerializedIRQDeliveryDoesNotOverlapConcurrentInjections(t *testing.T) {
	var delivery serializedIRQDelivery
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
	go func() {
		firstDone <- delivery.inject(irqChange{irq: 73, level: true}, apply)
	}()
	<-firstEntered

	// The second setter must not enter Hypervisor.framework until the first
	// call has returned; this also preserves the chosen mutex acquisition order.
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- delivery.inject(irqChange{irq: 73, level: false}, apply)
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("second IRQ injection overlapped the first: %v", err)
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

func TestSerializedIRQDeliveryReportsSetterFailure(t *testing.T) {
	var delivery serializedIRQDelivery
	want := errors.New("set SPI failed")
	err := delivery.inject(irqChange{irq: 73, level: true}, func(int, bool) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("inject error = %v, want %v", err, want)
	}
}
