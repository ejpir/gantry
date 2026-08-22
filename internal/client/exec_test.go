package client

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/ttrpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestSyncGuestUsesTrustedSystemService(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ttrpc.NewServer()
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	called := make(chan struct{})
	server.RegisterService(guestSystemService, &ttrpc.ServiceDesc{Methods: map[string]ttrpc.Method{
		"Sync": func(_ context.Context, unmarshal func(interface{}) error) (interface{}, error) {
			var request emptypb.Empty
			if err := unmarshal(&request); err != nil {
				return nil, err
			}
			close(called)
			return &emptypb.Empty{}, nil
		},
	}})
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		_ = listener.Close()
		<-serveDone
	})

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := ttrpc.NewClient(conn)
	t.Cleanup(func() { _ = client.Close() })
	if err := SyncGuest(client, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	default:
		t.Fatal("trusted system sync service was not called")
	}
}

func TestSessionKillTargetsWholeDedicatedTask(t *testing.T) {
	request := sessionKillRequest("sb-session-1")
	if request.ID != "sb-session-1" || request.ExecID != "" || !request.All {
		t.Fatalf("session kill request = %+v", request)
	}
}

func TestSessionTaskIDsAreUniqueUnderConcurrency(t *testing.T) {
	const count = 1000
	ids := make(chan string, count)
	var workers sync.WaitGroup
	for range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ids <- nextSessionTaskID("sb")
		}()
	}
	workers.Wait()
	close(ids)

	seen := make(map[string]struct{}, count)
	for id := range ids {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate session task ID %q", id)
		}
		if !strings.HasPrefix(id, "sb-session-") {
			t.Fatalf("session task ID %q has an unexpected prefix", id)
		}
		seen[id] = struct{}{}
	}
}
