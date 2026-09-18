package netpol

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrafficPublisherCloseJoinsFinalFlush(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var flushes atomic.Int32
	publisher := newTrafficPublisher(time.Hour, func() {
		flushes.Add(1)
		close(entered)
		<-release
	})

	const callers = 16
	var closes sync.WaitGroup
	closes.Add(callers)
	allDone := make(chan struct{})
	for range callers {
		go func() {
			defer closes.Done()
			publisher.Close()
		}()
	}
	go func() {
		closes.Wait()
		close(allDone)
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final flush did not start")
	}
	select {
	case <-allDone:
		t.Fatal("Close returned before the final flush completed")
	default:
	}
	close(release)
	select {
	case <-allDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close callers did not join publisher shutdown")
	}
	if got := flushes.Load(); got != 1 {
		t.Fatalf("final flushes = %d, want 1", got)
	}
}

func TestTrafficPersistenceRetriesWithoutLosingNewTraffic(t *testing.T) {
	store := newTrafficStore(TrafficSnapshot{Version: trafficSnapshotVersion})
	var writes atomic.Int32
	var persisted TrafficSnapshot
	persistence := newTrafficPersistence("ignored", store, func(_ string, data []byte) error {
		if writes.Add(1) == 1 {
			return errors.New("injected write failure")
		}
		return json.Unmarshal(data, &persisted)
	})

	store.markDirty()
	persistence.flush()
	store.observeTX(ipFrame(t, "192.0.2.1", protoTCP, 443, nil), true, time.Now())
	persistence.flush()

	if got := writes.Load(); got != 2 {
		t.Fatalf("writes = %d, want failed attempt plus retry", got)
	}
	if persisted.TXPackets != 1 || len(persisted.Entries) != 1 {
		t.Fatalf("retried snapshot = %+v", persisted)
	}
}

func TestTrafficPersistenceRetainsUpdatesDuringWrite(t *testing.T) {
	store := newTrafficStore(TrafficSnapshot{Version: trafficSnapshotVersion})
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	var writes atomic.Int32
	var latest TrafficSnapshot
	persistence := newTrafficPersistence("ignored", store, func(_ string, data []byte) error {
		if writes.Add(1) == 1 {
			close(writeStarted)
			<-releaseWrite
		}
		return json.Unmarshal(data, &latest)
	})

	store.markDirty()
	firstFlush := make(chan struct{})
	go func() {
		persistence.flush()
		close(firstFlush)
	}()
	select {
	case <-writeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first write did not start")
	}
	store.observeRX(inboundFrame(t, "192.0.2.2", protoTCP, 443, nil), time.Now())
	close(releaseWrite)
	select {
	case <-firstFlush:
	case <-time.After(5 * time.Second):
		t.Fatal("first write did not finish")
	}
	persistence.flush()

	if got := writes.Load(); got != 2 {
		t.Fatalf("writes = %d, want a follow-up write for concurrent traffic", got)
	}
	if latest.RXPackets != 1 || len(latest.Entries) != 1 {
		t.Fatalf("latest snapshot = %+v", latest)
	}
}
