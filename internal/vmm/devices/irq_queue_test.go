package devices

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestSerializedIRQDeliveryDoesNotOverlapConcurrentInjections(t *testing.T) {
	var delivery SerializedIRQDelivery
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var appliedMu sync.Mutex
	var applied []IRQChange
	apply := func(irq int, level bool) error {
		change := IRQChange{IRQ: irq, Level: level}
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
		firstDone <- delivery.Inject(IRQChange{IRQ: 73, Level: true}, apply)
	}()
	<-firstEntered

	// The second setter must not enter Hypervisor.framework until the first
	// call has returned; this also preserves the chosen mutex acquisition order.
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- delivery.Inject(IRQChange{IRQ: 73, Level: false}, apply)
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

	want := []IRQChange{{IRQ: 73, Level: true}, {IRQ: 73, Level: false}}
	if !reflect.DeepEqual(applied, want) {
		t.Fatalf("applied IRQ changes = %+v, want %+v", applied, want)
	}
}

func TestSerializedIRQDeliveryReportsSetterFailure(t *testing.T) {
	var delivery SerializedIRQDelivery
	want := errors.New("set SPI failed")
	err := delivery.Inject(IRQChange{IRQ: 73, Level: true}, func(int, bool) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("inject error = %v, want %v", err, want)
	}
}
