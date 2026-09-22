//go:build linux || darwin || windows

package sharefs

import (
	"sync"
	"testing"

	"github.com/ejpir/gantry/internal/sharefs/preparedstate"
)

func TestPreparedAdmitsOneConcurrentPublisher(t *testing.T) {
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hub.Close() }()
	prepared, _, err := hub.Prepare("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()

	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			<-start
			_, publishErr := hub.Publish(prepared)
			results <- publishErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded, failed := 0, 0
	for publishErr := range results {
		if publishErr == nil {
			succeeded++
		} else {
			failed++
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("publish results: succeeded=%d failed=%d", succeeded, failed)
	}
	if got := prepared.preparedState.Phase(); got != preparedstate.Consumed {
		t.Fatalf("prepared phase = %d, want consumed", got)
	}
	if export := hub.Export("code"); export == nil || export.State() != ExportActive {
		t.Fatalf("published export = %#v", export)
	}
}

func TestPreparedFailedForeignPublicationRetainsOwnership(t *testing.T) {
	owner, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	other, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	prepared, _, err := owner.Prepare("code", t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if _, err := other.Publish(prepared); err == nil {
		t.Fatal("foreign hub consumed prepared export")
	}
	if prepared.Identity().Path() == "" {
		t.Fatal("failed publication discarded prepared identity")
	}
	if _, err := owner.Publish(prepared); err != nil {
		t.Fatalf("owner could not publish after rejected attempt: %v", err)
	}
}
