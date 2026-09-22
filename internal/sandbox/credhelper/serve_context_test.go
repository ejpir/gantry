package credhelper

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServeContextClosesAndJoinsAcceptedConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- New(nil, nil, nil).ServeContext(ctx, listener) }()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	cancel()

	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("ServeContext did not join a blocked accepted connection")
	}
}
