package sshgw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/test/bufconn"
)

type recordingSpawner struct{ requests chan SpawnRequest }

func (s *recordingSpawner) Spawn(_ context.Context, request SpawnRequest) (int, error) {
	s.requests <- request
	switch {
	case request.Forward != nil:
		_, _ = io.WriteString(request.Stdout, "forwarded")
		return 0, nil
	case request.Command == "exit-seven":
		return 7, nil
	case request.Command == "wait-resize":
		select {
		case size := <-request.Resize:
			_, _ = io.WriteString(request.Stdout, fmt.Sprintf("%dx%d", size.Width, size.Height))
			return 0, nil
		case <-time.After(time.Second):
			return 255, errors.New("resize not received")
		}
	default:
		_, _ = io.WriteString(request.Stdout, request.Command)
		return 0, nil
	}
}

func startTestGateway(t *testing.T) (*ssh.Client, *recordingSpawner) {
	t.Helper()
	spawner := &recordingSpawner{requests: make(chan SpawnRequest, 8)}
	return startTestGatewayWithSpawner(t, spawner), spawner
}

func startTestGatewayWithSpawner(t *testing.T, spawner Spawner) *ssh.Client {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(Config{
		Name: "test", HostKeyPath: filepath.Join(t.TempDir(), "host_ed25519"),
		DefaultUser: "root", Spawner: spawner,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = listener.Close() })
	go func() { _ = gateway.Serve(ctx, listener) }()
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, listener.Addr().String(), &ssh.ClientConfig{
		User: "dev", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestGatewayCancellationClosesAcceptedConnections(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	gateway, err := New(Config{
		Name: "test", HostKeyPath: filepath.Join(t.TempDir(), "host_ed25519"),
		Spawner: SpawnFunc(func(context.Context, SpawnRequest) (int, error) { return 0, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = gateway.Serve(ctx, listener) }()
	raw, err := listener.Dial()
	if err != nil {
		t.Fatal(err)
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, "test", &ssh.ClientConfig{
		User: "dev", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { _ = client.Close() })

	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accepted SSH connection remained open after gateway cancellation")
	}
	if session, err := client.NewSession(); err == nil {
		_ = session.Close()
		t.Fatal("new SSH channel succeeded after gateway cancellation")
	}
}

func TestGatewayExecEnvironmentAndExitStatus(t *testing.T) {
	client, spawner := startTestGateway(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	if err := session.Setenv("LANG", "C.UTF-8"); err != nil {
		t.Fatalf("allowlisted LANG refused: %v", err)
	}
	if err := session.Setenv("GITHUB_TOKEN", "must-not-pass"); err == nil {
		t.Fatal("non-allowlisted environment variable accepted")
	}
	err = session.Run("exit-seven")
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 7 {
		t.Fatalf("Run error = %v, want exit status 7", err)
	}
	request := <-spawner.requests
	if request.User != "dev" || request.Command != "exit-seven" {
		t.Fatalf("spawn request = user %q command %q", request.User, request.Command)
	}
	if strings.Join(request.Env, " ") != "LANG=C.UTF-8" {
		t.Fatalf("spawn environment = %v", request.Env)
	}
}

func TestGatewayPTYAndResize(t *testing.T) {
	client, spawner := startTestGateway(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	output := new(strings.Builder)
	session.Stdout = output
	if err := session.Start("wait-resize"); err != nil {
		t.Fatal(err)
	}
	request := <-spawner.requests
	if !request.Terminal || request.Window != (Window{Width: 80, Height: 24}) {
		t.Fatalf("initial PTY request = terminal %v window %#v", request.Terminal, request.Window)
	}
	if err := session.WindowChange(40, 120); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "120x40" {
		t.Fatalf("resize output = %q", output.String())
	}
}

type blockingForwardSpawner struct {
	started  chan struct{}
	canceled chan struct{}
}

func (s *blockingForwardSpawner) Spawn(ctx context.Context, request SpawnRequest) (int, error) {
	if request.Forward == nil {
		return 0, nil
	}
	close(s.started)
	<-ctx.Done()
	close(s.canceled)
	return 255, ctx.Err()
}

func TestGatewayClosedDirectTCPIPChannelCancelsRelay(t *testing.T) {
	spawner := &blockingForwardSpawner{started: make(chan struct{}), canceled: make(chan struct{})}
	client := startTestGatewayWithSpawner(t, spawner)
	forward, err := client.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-spawner.started:
	case <-time.After(time.Second):
		t.Fatal("guest relay did not start")
	}
	if err := forward.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-spawner.canceled:
	case <-time.After(time.Second):
		t.Fatal("closed forwarding channel did not cancel guest relay")
	}

	// Closing one channel must not close the parent SSH connection.
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("open session after forwarding close: %v", err)
	}
	defer func() { _ = session.Close() }()
	if err := session.Run("still-alive"); err != nil {
		t.Fatalf("run session after forwarding close: %v", err)
	}
}

type halfCloseForwardSpawner struct{}

func (halfCloseForwardSpawner) Spawn(ctx context.Context, request SpawnRequest) (int, error) {
	if request.Forward == nil {
		return 0, nil
	}
	payload, err := io.ReadAll(request.Stdin)
	if err != nil {
		return 255, err
	}
	select {
	case <-ctx.Done():
		return 255, errors.New("half-close canceled relay")
	default:
	}
	_, err = io.WriteString(request.Stdout, "response:"+string(payload))
	return 0, err
}

func TestGatewayDirectTCPIPHalfClosePreservesResponse(t *testing.T) {
	client := startTestGatewayWithSpawner(t, halfCloseForwardSpawner{})
	forward, err := client.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = forward.Close() }()
	if _, err := io.WriteString(forward, "request"); err != nil {
		t.Fatal(err)
	}
	half, ok := forward.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("SSH forwarding connection does not support CloseWrite")
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(forward)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response:request" {
		t.Fatalf("response after half-close = %q", response)
	}
}

func TestGatewayDirectTCPIPPolicy(t *testing.T) {
	client, spawner := startTestGateway(t)
	conn, err := client.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if string(payload) != "forwarded" {
		t.Fatalf("forward payload = %q", payload)
	}
	request := <-spawner.requests
	if request.Forward == nil || request.Forward.Host != "127.0.0.1" || request.Forward.Port != 8080 {
		t.Fatalf("forward request = %#v", request.Forward)
	}
	if _, err := client.Dial("tcp", "8.8.8.8:53"); err == nil || !strings.Contains(err.Error(), GenericChannelRefusal()) {
		t.Fatalf("non-loopback forward error = %v", err)
	}
}
