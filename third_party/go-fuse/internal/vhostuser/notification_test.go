package vhostuser

import (
	"encoding/binary"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testEpochNotification() []byte {
	message := make([]byte, 16)
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.LittleEndian.PutUint32(message[4:8], 8) // FUSE_NOTIFY_INC_EPOCH
	return message
}

func TestNotificationEnqueueWhileRequestHoldsCompletionReadLock(t *testing.T) {
	completionMu := new(sync.RWMutex)
	queue := newNotificationQueue(&Virtq{completionMu: completionMu}, nil)

	enqueued := make(chan syscall.Errno, 1)
	releaseRequest := make(chan struct{})
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		completionMu.RLock()
		defer completionMu.RUnlock()
		enqueued <- queue.enqueue(testEpochNotification())
		<-releaseRequest
	}()

	select {
	case errno := <-enqueued:
		if errno != 0 {
			t.Fatalf("enqueue errno = %v", errno)
		}
	case <-time.After(time.Second):
		t.Fatal("notification enqueue deadlocked behind its request's completion read lock")
	}

	// Delivery must remain deferred until request completion. There is no
	// writable notification slot in this unit test, so the message stays queued.
	queue.mu.Lock()
	if !queue.flushScheduled || len(queue.pending) != 1 {
		t.Fatalf("before request completion: scheduled=%v pending=%d, want true/1",
			queue.flushScheduled, len(queue.pending))
	}
	queue.mu.Unlock()

	close(releaseRequest)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not release completion read lock")
	}

	deadline := time.Now().Add(time.Second)
	for {
		queue.mu.Lock()
		scheduled := queue.flushScheduled
		pending := len(queue.pending)
		queue.mu.Unlock()
		if !scheduled {
			if pending != 1 {
				t.Fatalf("pending notifications = %d, want 1 without a guest slot", pending)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deferred notification flush did not run after request completion")
		}
		time.Sleep(time.Millisecond)
	}
}
