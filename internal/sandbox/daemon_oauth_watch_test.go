package sandbox

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge/watchproto"
)

func freeOAuthWatchPort(t *testing.T) int {
	t.Helper()
	for port := 55000; port < 65000; port++ {
		ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port
	}
	t.Fatal("no free OAuth watch port")
	return 0
}

func testOAuthWatchBridge(t *testing.T) *oauthbridge.Bridge {
	t.Helper()
	b := oauthbridge.New(func([]string, time.Duration) ([]byte, int, error) {
		return []byte("HTTP/1.0 200 OK\r\n\r\n"), 0, nil
	}, true)
	if b == nil {
		t.Fatal("OAuth bridge was not created")
	}
	t.Cleanup(b.CloseGuestListeners)
	return b
}

func TestOAuthWatchDecoderTracksSnapshots(t *testing.T) {
	b := testOAuthWatchBridge(t)
	port := freeOAuthWatchPort(t)
	var logs []string
	decoder := newOAuthWatchDecoder(b, func(format string, a ...any) {
		logs = append(logs, fmt.Sprintf(format, a...))
	})

	baseline := "{\"ports\":[]}\n"
	cut := len(baseline) / 2
	if n, err := decoder.Write([]byte(baseline[:cut])); err != nil || n != cut {
		t.Fatalf("first write = %d, %v", n, err)
	}
	select {
	case <-decoder.Ready():
		t.Fatal("partial snapshot marked watcher ready")
	default:
	}
	if n, err := decoder.Write([]byte(baseline[cut:])); err != nil || n != len(baseline)-cut {
		t.Fatalf("second write = %d, %v", n, err)
	}
	select {
	case <-decoder.Ready():
	case <-time.After(time.Second):
		t.Fatal("valid snapshot did not mark watcher ready")
	}

	line := fmt.Sprintf(`{"ports":[%d]}`+"\n", port)
	if _, err := decoder.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("host callback gate was not opened: %v", err)
	}
	_ = conn.Close()

	if _, err := decoder.Write([]byte("{\"ports\":[]}\n")); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("removed guest listener left host callback gate open")
	}
	if len(logs) != 0 {
		t.Fatalf("unexpected decoder logs: %v", logs)
	}
}

func TestOAuthWatchDecoderRejectsMalformedAndOversizedSnapshots(t *testing.T) {
	b := testOAuthWatchBridge(t)
	var logs []string
	decoder := newOAuthWatchDecoder(b, func(format string, a ...any) {
		logs = append(logs, fmt.Sprintf(format, a...))
	})
	_, _ = decoder.Write([]byte("not-json\n"))
	_, _ = decoder.Write([]byte(strings.Repeat("x", watchproto.MaxMessageBytes+1) + "\n"))
	select {
	case <-decoder.Ready():
		t.Fatal("invalid snapshots marked watcher ready")
	default:
	}
	if len(logs) != 2 || !strings.Contains(logs[0], "malformed") || !strings.Contains(logs[1], "oversized") {
		t.Fatalf("decoder logs = %v", logs)
	}
}

func TestOAuthWatchDecoderCloseRemovesDiscoveredListeners(t *testing.T) {
	b := testOAuthWatchBridge(t)
	port := freeOAuthWatchPort(t)
	decoder := newOAuthWatchDecoder(b, nil)
	_, _ = decoder.Write([]byte("{\"ports\":[]}\n"))
	_, _ = fmt.Fprintf(decoder, `{"ports":[%d]}`+"\n", port)
	decoder.Close()
	decoder.Close()
	if conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("decoder close left host callback gate open")
	}
}
