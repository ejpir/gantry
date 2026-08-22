package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/ttrpc"
	"github.com/ejpir/gantry/internal/image"
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

func TestSessionExecIDsAreUniqueUnderConcurrency(t *testing.T) {
	const count = 1000
	ids := make(chan string, count)
	var workers sync.WaitGroup
	for range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ids <- nextSessionExecID("sb")
		}()
	}
	workers.Wait()
	close(ids)

	seen := make(map[string]struct{}, count)
	for id := range ids {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate exec ID %q", id)
		}
		seen[id] = struct{}{}
	}
}

type execLifecycleTask struct {
	task.TTRPCTaskService

	mu        sync.Mutex
	events    []string
	startErr  error
	startHook func() error
	waitHook  func()
	deleteErr error
}

func (f *execLifecycleTask) record(event string) {
	f.mu.Lock()
	f.events = append(f.events, event)
	f.mu.Unlock()
}

func (f *execLifecycleTask) Exec(context.Context, *task.ExecProcessRequest) (*emptypb.Empty, error) {
	f.record("exec")
	return &emptypb.Empty{}, nil
}

func (f *execLifecycleTask) Start(context.Context, *task.StartRequest) (*task.StartResponse, error) {
	f.record("start")
	if f.startHook != nil {
		if err := f.startHook(); err != nil {
			return &task.StartResponse{}, err
		}
	}
	return &task.StartResponse{}, f.startErr
}

func (f *execLifecycleTask) Wait(context.Context, *task.WaitRequest) (*task.WaitResponse, error) {
	f.record("wait")
	if f.waitHook != nil {
		f.waitHook()
	}
	return &task.WaitResponse{ExitStatus: 7}, nil
}

func (f *execLifecycleTask) Delete(context.Context, *task.DeleteRequest) (*task.DeleteResponse, error) {
	f.record("delete")
	return &task.DeleteResponse{}, f.deleteErr
}

func (f *execLifecycleTask) Events() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func testStreamDial() (func() (net.Conn, error), func(), <-chan struct{}) {
	var mu sync.Mutex
	stream := 0
	stdoutPeer := make(chan net.Conn)
	stdinEOF := make(chan struct{})
	dial := func() (net.Conn, error) {
		client, server := net.Pipe()
		mu.Lock()
		current := stream
		stream++
		mu.Unlock()
		go func() {
			defer func() { _ = server.Close() }()
			_ = server.SetDeadline(time.Now().Add(2 * time.Second))
			var size [4]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			name := make([]byte, binary.BigEndian.Uint32(size[:]))
			if _, err := io.ReadFull(server, name); err != nil {
				return
			}
			packet := make([]byte, 4+len(name))
			binary.BigEndian.PutUint32(packet[:4], uint32(len(name)))
			copy(packet[4:], name)
			if _, err := server.Write(packet); err != nil {
				return
			}
			if current == 0 { // stdin: drain through the relay's explicit EOF close.
				_, _ = io.Copy(io.Discard, server)
				close(stdinEOF)
				return
			}
			// The guest owns stdout after the handshake and closes it when the
			// process exits. Wait triggers that transition in the fake task.
			stdoutPeer <- server
		}()
		return client, nil
	}
	var closeOnce sync.Once
	closeOutput := func() {
		closeOnce.Do(func() { _ = (<-stdoutPeer).Close() })
	}
	return dial, closeOutput, stdinEOF
}

// startBlockingOutputDial returns the guest side of stdout after its stream
// handshake. Writing to that net.Pipe blocks until the client's relay is
// already reading, which makes relay-before-Start ordering deterministic.
func startBlockingOutputDial() (func() (net.Conn, error), <-chan net.Conn) {
	var mu sync.Mutex
	stream := 0
	stdoutPeer := make(chan net.Conn, 1)
	dial := func() (net.Conn, error) {
		client, server := net.Pipe()
		mu.Lock()
		current := stream
		stream++
		mu.Unlock()
		go func() {
			_ = server.SetDeadline(time.Now().Add(2 * time.Second))
			var size [4]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				_ = server.Close()
				return
			}
			name := make([]byte, binary.BigEndian.Uint32(size[:]))
			if _, err := io.ReadFull(server, name); err != nil {
				_ = server.Close()
				return
			}
			packet := make([]byte, 4+len(name))
			binary.BigEndian.PutUint32(packet[:4], uint32(len(name)))
			copy(packet[4:], name)
			if _, err := server.Write(packet); err != nil {
				_ = server.Close()
				return
			}
			_ = server.SetDeadline(time.Time{})
			if current == 0 {
				_, _ = io.Copy(io.Discard, server)
				_ = server.Close()
				return
			}
			stdoutPeer <- server
		}()
		return client, nil
	}
	return dial, stdoutPeer
}

func TestSessionExecDeletesProcessAfterWait(t *testing.T) {
	t.Parallel()
	dial, closeOutput, stdinEOF := testStreamDial()
	defer closeOutput()
	service := &execLifecycleTask{
		startHook: func() error {
			select {
			case <-stdinEOF:
				return errors.New("stdin reached EOF before task Start")
			default:
				return nil
			}
		},
		waitHook: func() {
			select {
			case <-stdinEOF:
			case <-time.After(time.Second):
			}
			closeOutput()
		},
	}
	status := 0
	err := sessionExec(service, SessionOptions{
		Args:       []string{"true"},
		ImgCfg:     &image.Config{},
		StreamDial: dial,
		Quiet:      true,
		ExitStatus: &status,
	}, "sandbox", strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if status != 7 {
		t.Fatalf("exit status = %d, want 7", status)
	}
	if want := []string{"exec", "start", "wait", "delete"}; !reflect.DeepEqual(service.Events(), want) {
		t.Fatalf("events = %v, want %v", service.Events(), want)
	}
}

func TestSessionExecRelaysOutputBeforeStart(t *testing.T) {
	t.Parallel()
	dial, stdoutPeer := startBlockingOutputDial()
	service := &execLifecycleTask{}
	service.startHook = func() error {
		peer := <-stdoutPeer
		defer func() { _ = peer.Close() }()
		if err := peer.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return err
		}
		_, err := peer.Write([]byte("fast output"))
		return err
	}
	var output strings.Builder
	err := sessionExec(service, SessionOptions{
		Args:       []string{"true"},
		ImgCfg:     &image.Config{},
		StreamDial: dial,
		Quiet:      true,
	}, "sandbox", strings.NewReader(""), &output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "fast output") {
		t.Fatalf("stdout = %q, want fast process output", output.String())
	}
}

func TestSessionExecDeletesProcessAfterStartFailure(t *testing.T) {
	t.Parallel()
	startErr := errors.New("start failed")
	dial, closeOutput, _ := testStreamDial()
	defer closeOutput()
	service := &execLifecycleTask{startErr: startErr}
	err := sessionExec(service, SessionOptions{
		Args:       []string{"true"},
		ImgCfg:     &image.Config{},
		StreamDial: dial,
		Quiet:      true,
	}, "sandbox", strings.NewReader(""), io.Discard)
	if !errors.Is(err, startErr) {
		t.Fatalf("error = %v, want start failure", err)
	}
	if want := []string{"exec", "start", "delete"}; !reflect.DeepEqual(service.Events(), want) {
		t.Fatalf("events = %v, want %v", service.Events(), want)
	}
}

func TestSessionExecReportsDeleteFailure(t *testing.T) {
	t.Parallel()
	deleteErr := errors.New("delete failed")
	dial, closeOutput, _ := testStreamDial()
	defer closeOutput()
	service := &execLifecycleTask{waitHook: closeOutput, deleteErr: deleteErr}
	err := sessionExec(service, SessionOptions{
		Args:       []string{"true"},
		ImgCfg:     &image.Config{},
		StreamDial: dial,
		Quiet:      true,
	}, "sandbox", strings.NewReader(""), io.Discard)
	if !errors.Is(err, deleteErr) {
		t.Fatalf("error = %v, want delete failure", err)
	}
}
