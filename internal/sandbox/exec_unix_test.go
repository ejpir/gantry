//go:build !windows

package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

const execEOFOutput = "before EOF\nafter EOF\n\x00{\"v\":1,\"exit\":0}\n"

// Exercise the actual CLI entry point in a child, without swapping the test
// process's global stdio or needing a VM. The fake broker waits for stdin EOF
// before sending its final output and out-of-band exit event, like mcp-proxy.
func TestCmdSandboxExecForwardsStdinEOF(t *testing.T) {
	if os.Getenv("GANTRY_TEST_EXEC_EOF_HELPER") == "1" {
		os.Exit(CmdSandboxExec("eof", []string{"--", "mcp-proxy"}))
	}
	// Keep AF_UNIX paths below Darwin's 104-byte limit.
	home, err := os.MkdirTemp("", "g-exec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("GANTRY_HOME", home)
	dir := layout.Dir("eof")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := layout.HoldLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		input string
		event *controlproto.SessionExitEvent
		want  int
	}{
		{"empty stdin", "", &controlproto.SessionExitEvent{V: controlproto.SessionProtocolVersion, Exit: 0}, 0},
		{"pipelined stdin and nonzero exit", strings.Repeat("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n", 2048), &controlproto.SessionExitEvent{V: controlproto.SessionProtocolVersion, Exit: 7}, 7},
		{"missing exit event fails closed", "request\n", nil, controlproto.SessionAbnormalExitCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "ctl.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
			served := make(chan error, 1)
			go func() { served <- serveExecEOFFixture(listener, tc.input, tc.event) }()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCmdSandboxExecForwardsStdinEOF$")
			command.Env = append(os.Environ(), "GANTRY_TEST_EXEC_EOF_HELPER=1")
			command.Stdin = strings.NewReader(tc.input)
			output, runErr := command.CombinedOutput()
			if err := <-served; err != nil {
				t.Errorf("fake broker: %v", err)
			}
			if command.ProcessState == nil || command.ProcessState.ExitCode() != tc.want {
				t.Fatalf("exec = %v (%v), want exit %d; output: %q", command.ProcessState, runErr, tc.want, output)
			}
			if !strings.HasPrefix(string(output), execEOFOutput) {
				t.Fatalf("exec lost output after stdin EOF: %q", output)
			}
		})
	}
}

func serveExecEOFFixture(listener net.Listener, input string, event *controlproto.SessionExitEvent) error {
	var control, data net.Conn
	var reader *bufio.Reader
	var id string
	for _, op := range []string{"sessionctl", "session"} {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader = bufio.NewReader(conn)
		line, err := controlproto.ReadBoundedLine(reader, controlproto.MaxRequestBytes)
		if err != nil {
			return err
		}
		var request controlproto.Request
		if err := json.Unmarshal(line, &request); err != nil {
			return err
		}
		if request.Op != op || request.ID == "" || request.Terminal {
			return fmt.Errorf("unexpected handshake: %+v", request)
		}
		if op == "sessionctl" {
			control, id = conn, request.ID
			if request.V != controlproto.SessionProtocolVersion {
				return fmt.Errorf("unsupported control version %d", request.V)
			}
		} else {
			data = conn
			if request.ID != id {
				return fmt.Errorf("session ID differs from parked control")
			}
		}
		if _, err := io.WriteString(conn, "{\"ok\":true}\n"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(data, "before EOF\n"); err != nil {
		return err
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("waiting for stdin EOF: %w", err)
	}
	if string(got) != input {
		return fmt.Errorf("stdin truncated or changed: got %d bytes, want %d", len(got), len(input))
	}
	// Only half-close stdin: these bytes must remain readable by the client.
	// Include a fake in-band exit marker to verify the real exit event wins.
	if _, err := io.WriteString(data, strings.TrimPrefix(execEOFOutput, "before EOF\n")); err != nil {
		return err
	}
	if event != nil {
		return json.NewEncoder(control).Encode(event)
	}
	return nil
}
