package mcpworker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/mcpgw"
	"github.com/ejpir/gantry/internal/workerproto"
)

func TestMuxBidirectionalOpenAndRelay(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	left := NewMux(leftConn, true, func(_ context.Context, request OpenRequest, stream *Stream) error {
		if request.Kind != StreamRemote || request.Server != "remote" {
			return fmt.Errorf("open request = %+v", request)
		}
		go func() {
			buffer := make([]byte, 32)
			n, err := stream.Read(buffer)
			if err == nil {
				_, _ = stream.Write([]byte(strings.ToUpper(string(buffer[:n]))))
			}
			_ = stream.Close()
		}()
		return nil
	})
	right := NewMux(rightConn, false, nil)
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := right.Open(ctx, OpenRequest{Kind: StreamRemote, Server: "remote"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := stream.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "HELLO" {
		t.Fatalf("response = %q", buffer)
	}
}

func TestMuxClosingUnreadStreamUnblocksOtherStreams(t *testing.T) {
	leftConn, rightConn := net.Pipe()
	writerDone := make(chan struct{})
	left := NewMux(leftConn, true, func(_ context.Context, request OpenRequest, stream *Stream) error {
		switch request.Server {
		case "flood":
			go func() {
				defer close(writerDone)
				payload := make([]byte, 2<<20)
				_, _ = stream.Write(payload)
				_ = stream.Close()
			}()
		case "echo":
			go func() {
				buffer := make([]byte, 4)
				n, _ := stream.Read(buffer)
				_, _ = stream.Write(buffer[:n])
				_ = stream.Close()
			}()
		default:
			return fmt.Errorf("unknown test server")
		}
		return nil
	})
	right := NewMux(rightConn, false, nil)
	defer func() { _ = left.Close(); _ = right.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	flood, err := right.Open(ctx, OpenRequest{Kind: StreamRemote, Server: "flood"})
	if err != nil {
		t.Fatal(err)
	}
	// Do not read the flood. Closing it must unblock the mux reader even after
	// its bounded per-stream queue filled.
	time.Sleep(10 * time.Millisecond)
	_ = flood.Close()
	select {
	case <-writerDone:
	case <-ctx.Done():
		t.Fatal("flood writer remained blocked after stream close")
	}
	echo, err := right.Open(ctx, OpenRequest{Kind: StreamRemote, Server: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = echo.Write([]byte("pong"))
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(echo, buffer); err != nil || string(buffer) != "pong" {
		t.Fatalf("unrelated stream after flood = %q, %v", buffer, err)
	}
}

func TestRunGatewayOverBrokeredStreams(t *testing.T) {
	controlSupervisor, controlWorker := net.Pipe()
	brokerSupervisor, brokerWorker := net.Pipe()
	streamsSupervisor, streamsWorker := net.Pipe()
	workerDone := make(chan error, 1)
	go func() { workerDone <- Run(controlWorker, brokerWorker, streamsWorker) }()

	config := Config{Version: ProtocolVersion, Confinement: "off", Servers: []ServerConfig{{
		Name: "fs", Local: true,
		Tools: mcpgw.ToolPolicy{Allow: []string{"read_file"}},
	}}}
	nonce := []byte("0123456789abcdef0123456789abcdef")
	if err := workerproto.SendHandshake(controlSupervisor, workerproto.RoleMCP, nonce, config); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(brokerSupervisor, nonce); err != nil {
		t.Fatal(err)
	}
	if err := workerproto.WriteNonce(streamsSupervisor, nonce); err != nil {
		t.Fatal(err)
	}

	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- workerproto.ServeRequests(brokerSupervisor, map[string]workerproto.Handler{
			OpAudit: func(request workerproto.Request) (any, error) {
				var body AuditRequest
				return nil, workerproto.DecodeBody(request, &body)
			},
			OpCredential: func(workerproto.Request) (any, error) {
				return nil, fmt.Errorf("local server requested a credential")
			},
		})
	}()

	capability := strings.Repeat("0", 32)
	mux := NewMux(streamsSupervisor, true, func(_ context.Context, request OpenRequest, stream *Stream) error {
		if request.Kind != StreamLocal || request.Server != "fs" || request.Session != capability {
			return net.ErrClosed
		}
		go fakeFilesystemServer(stream)
		return nil
	})
	defer func() { _ = mux.Close() }()

	var ack BootAck
	if err := workerproto.ReadMessage(controlSupervisor, &ack); err != nil {
		t.Fatal(err)
	}
	if !ack.OK || ack.Confinement == nil || ack.Confinement.Mode != "off" {
		t.Fatalf("boot ack = %+v", ack)
	}
	client := workerproto.NewClient(controlSupervisor)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	guest, err := mux.Open(ctx, OpenRequest{Kind: StreamGuest, Session: capability})
	if err != nil {
		t.Fatal(err)
	}
	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}
	for _, request := range requests {
		if _, err := guest.Write([]byte(request + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	_ = guest.SetReadDeadline(time.Now().Add(5 * time.Second))
	scanner := bufio.NewScanner(guest)
	var output strings.Builder
	for scanner.Scan() {
		output.Write(scanner.Bytes())
		if strings.Contains(output.String(), "fs__read_file") {
			break
		}
	}
	if !strings.Contains(output.String(), "fs__read_file") {
		t.Fatalf("gateway response = %s (scan err %v)", output.String(), scanner.Err())
	}
	_ = guest.Close()
	if err := client.CallWithTimeout(OpShutdown, nil, nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-workerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
	_ = brokerSupervisor.Close()
	<-brokerDone
}

func fakeFilesystemServer(stream *Stream) {
	defer func() { _ = stream.Close() }()
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(scanner.Bytes(), &request) != nil || len(request.ID) == 0 {
			continue
		}
		var result any
		switch request.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18"}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{{"name": "read_file"}}}
		default:
			result = map[string]any{}
		}
		response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
		_, _ = stream.Write(append(response, '\n'))
	}
}
