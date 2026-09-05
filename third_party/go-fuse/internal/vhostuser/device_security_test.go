//go:build unix

package vhostuser

import (
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSetVringNumRejectsNonPowerOfTwo(t *testing.T) {
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()

	for _, size := range []uint32{3, 7, 127} {
		if err := device.SetVringNum(&VhostVringState{Index: 0, Num: size}); err == nil {
			t.Errorf("accepted non-power-of-two queue size %d", size)
		}
	}
	for _, size := range []uint32{1, 2, 64, 128} {
		if err := device.SetVringNum(&VhostVringState{Index: 0, Num: size}); err != nil {
			t.Errorf("rejected queue size %d: %v", size, err)
		}
	}
}

func TestSetVringNumRejectsMappedResize(t *testing.T) {
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()
	queue := device.vqs[0]
	queue.Vring.Num = 1
	queue.Vring.Avail = &VringAvail{}
	queue.Vring.AvailRing = make([]uint16, 1)
	queue.Vring.UsedRing = make([]VringUsedElement, 1)

	if err := device.SetVringNum(&VhostVringState{Index: 0, Num: 128}); err == nil {
		t.Fatal("resized a mapped queue")
	}
	if queue.Vring.Num != 1 || len(queue.Vring.AvailRing) != 1 || len(queue.Vring.UsedRing) != 1 {
		t.Fatalf("mapped queue changed after rejection: num=%d avail=%d used=%d", queue.Vring.Num, len(queue.Vring.AvailRing), len(queue.Vring.UsedRing))
	}
}

func TestSetVringAddrRejectsMappedRelocation(t *testing.T) {
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()
	queue := device.vqs[0]
	original := VhostVringAddr{Index: 0, DescUserAddr: 0x1000, AvailUserAddr: 0x2000, UsedUserAddr: 0x3000}
	queue.Addr = original
	queue.Vring.Avail = &VringAvail{}

	if err := device.SetVringAddr(&original); err != nil {
		t.Fatalf("idempotent mapped address rejected: %v", err)
	}
	changed := original
	changed.DescUserAddr = 0x4000
	if err := device.SetVringAddr(&changed); err == nil {
		t.Fatal("relocated a mapped queue")
	}
	if queue.Addr != original {
		t.Fatalf("mapped queue address changed after rejection: got %+v, want %+v", queue.Addr, original)
	}
}

func TestSetVringEnableRequiresCompleteQueue(t *testing.T) {
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()

	if err := device.SetVringEnable(&VhostVringState{Index: 0, Num: 1}); err == nil {
		t.Fatal("enabled a queue without mapped rings and doorbells")
	}
}

func TestSetFeaturesConcurrentNotify(t *testing.T) {
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()
	queue := device.vqs[0]
	usedEvent := uint16(0)
	queue.Vring.Avail = &VringAvail{}
	queue.Vring.AvailUsedEvent = &usedEvent

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 10_000; i++ {
			device.SetFeatures([]int{RING_F_EVENT_IDX})
			device.SetFeatures(nil)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 10_000; i++ {
			queue.vringNotify()
		}
	}()
	close(start)
	workers.Wait()
}

func TestDoorbellSettersRejectWrongPipeDirection(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()

	readFD, err := syscall.Dup(int(readEnd.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := device.SetVringCall(readFD, 0); err == nil {
		syscall.Close(readFD)
		t.Fatal("accepted a read-only call doorbell")
	}
	syscall.Close(readFD)

	writeFD, err := syscall.Dup(int(writeEnd.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := device.SetVringKick(writeFD, 0); err == nil {
		syscall.Close(writeFD)
		t.Fatal("accepted a write-only kick doorbell")
	}
	syscall.Close(writeFD)
}

func TestQueueNotifyFullCallPipeDoesNotPanic(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	writeFD := int(writeEnd.Fd())
	if err := syscall.SetNonblock(writeFD, true); err != nil {
		t.Fatal(err)
	}
	var block [4096]byte
	for {
		if _, err := syscall.Write(writeFD, block[:]); err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				break
			}
			t.Fatal(err)
		}
	}

	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()
	queue := device.vqs[0]
	queue.Vring.Avail = &VringAvail{}
	queue.CallFD, err = syscall.Dup(writeFD)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetNonblock(queue.CallFD, true); err != nil {
		t.Fatal(err)
	}

	queue.queueNotify()
}

func TestQueueNotifyMissingCallFDDoesNotPanic(t *testing.T) {
	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()
	device.vqs[0].Vring.Avail = &VringAvail{}

	device.vqs[0].queueNotify()
}

func TestQueueNotifyBrokenCallPipeDoesNotPanic(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readEnd.Close()
	defer writeEnd.Close()

	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	defer device.Close()
	queue := device.vqs[0]
	queue.Vring.Avail = &VringAvail{}
	queue.CallFD, err = syscall.Dup(int(writeEnd.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	queue.queueNotify()
}

func TestDeviceCloseWakesIdleKickReader(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	readFD, err := syscall.Dup(int(readEnd.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	writeFD, err := syscall.Dup(int(writeEnd.Fd()))
	if err != nil {
		syscall.Close(readFD)
		t.Fatal(err)
	}

	device := NewDeviceWithQueues(1, func(*VirtqElem) int { return 0 })
	queue := device.vqs[0]
	queue.Vring.Num = 1
	queue.Vring.Avail = &VringAvail{}
	if err := device.SetVringKick(readFD, 0); err != nil {
		syscall.Close(readFD)
		syscall.Close(writeFD)
		t.Fatal(err)
	}
	if err := device.SetVringCall(writeFD, 0); err != nil {
		syscall.Close(writeFD)
		t.Fatal(err)
	}
	if err := device.SetVringEnable(&VhostVringState{Index: 0, Num: 1}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- device.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Device.Close blocked on an idle kick descriptor")
	}
}
