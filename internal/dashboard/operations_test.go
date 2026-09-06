package dashboard

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

func TestCommandOutputBoundsTailAndPartialLines(t *testing.T) {
	events := make(chan tuiProcessStreamEvent, 16)
	output := &tuiProcessOutput{events: events}
	data := bytes.Repeat([]byte("x"), 4*tuiOutputLimit)
	if n, err := output.Write(data); err != nil || n != len(data) {
		t.Fatalf("Write=%d %v", n, err)
	}
	if output.output.Len() > tuiOutputLimit || len(output.pending) > tuiLineLimit {
		t.Fatal("output exceeded its budget")
	}
	// A later complete progress line still works after discarding a huge line.
	tail := "\ndownloading fixture [50%]\nfinal diagnostic\n"
	if _, err := output.Write([]byte(tail)); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(output.String(), tail) {
		t.Fatal("newest diagnostic lost")
	}
	select {
	case event := <-events:
		if event.progress != "downloading fixture [50%]" {
			t.Fatalf("progress=%q", event.progress)
		}
	default:
		t.Fatal("progress did not recover after oversized line")
	}
}

type waitingLifecycle struct {
	entered chan struct{}
	exited  chan struct{}
}

func (service waitingLifecycle) Start(ctx context.Context, request lifecycle.StartRequest, observer lifecycle.Observer) (lifecycle.StartResult, error) {
	close(service.entered)
	observer(lifecycle.Progress{Phase: "prepare", Message: "a structured event with no CLI marker"})
	<-ctx.Done()
	close(service.exited)
	return lifecycle.StartResult{}, ctx.Err()
}

func TestDashboardCloseCancelsAndJoinsLifecycle(t *testing.T) {
	group := newDashboardOperations()
	service := waitingLifecycle{entered: make(chan struct{}), exited: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		message := runTUIStartCmd(group, service, "create", lifecycle.StartRequest{Name: "dev"})()
		stream, ok := message.(tuiProcessStreamMsg)
		if !ok || stream.event.progress != "a structured event with no CLI marker" {
			t.Errorf("progress=%+v", message)
		}
	}()
	select {
	case <-service.entered:
	case <-time.After(time.Second):
		t.Fatal("operation did not start")
	}
	group.close()
	select {
	case <-service.exited:
	default:
		t.Fatal("close returned before lifecycle finished")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UI command did not return")
	}
	if group.begin() {
		group.end()
		t.Fatal("closed dashboard admitted a new operation")
	}
	if !errors.Is(group.ctx.Err(), context.Canceled) {
		t.Fatal("operation context was not cancelled")
	}
}
