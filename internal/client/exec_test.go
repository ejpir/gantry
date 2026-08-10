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
	"github.com/ejpir/gantry/internal/image"
	"google.golang.org/protobuf/types/known/emptypb"
)

type execLifecycleTask struct {
	task.TTRPCTaskService

	mu        sync.Mutex
	events    []string
	startErr  error
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
	return &task.StartResponse{}, f.startErr
}

func (f *execLifecycleTask) Wait(context.Context, *task.WaitRequest) (*task.WaitResponse, error) {
	f.record("wait")
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

func testStreamDial() func() (net.Conn, error) {
	var mu sync.Mutex
	stream := 0
	return func() (net.Conn, error) {
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
			if current == 0 { // stdin: drain until session cleanup closes it.
				_, _ = io.Copy(io.Discard, server)
			}
		}()
		return client, nil
	}
}

func TestSessionExecDeletesProcessAfterWait(t *testing.T) {
	t.Parallel()
	service := &execLifecycleTask{}
	status := 0
	err := sessionExec(service, SessionOptions{
		Args:       []string{"true"},
		ImgCfg:     &image.Config{},
		StreamDial: testStreamDial(),
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

func TestSessionExecDeletesProcessAfterStartFailure(t *testing.T) {
	t.Parallel()
	startErr := errors.New("start failed")
	service := &execLifecycleTask{startErr: startErr}
	err := sessionExec(service, SessionOptions{
		Args:       []string{"true"},
		ImgCfg:     &image.Config{},
		StreamDial: testStreamDial(),
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
	service := &execLifecycleTask{deleteErr: deleteErr}
	err := sessionExec(service, SessionOptions{
		Args:       []string{"true"},
		ImgCfg:     &image.Config{},
		StreamDial: testStreamDial(),
		Quiet:      true,
	}, "sandbox", strings.NewReader(""), io.Discard)
	if !errors.Is(err, deleteErr) {
		t.Fatalf("error = %v, want delete failure", err)
	}
}
