//go:build !windows

package sandbox

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
)

func TestSendSessionResizeAsksTheBrokerForTheSession(t *testing.T) {
	// Short: Unix socket paths are limited, and macOS temp dirs are long.
	dir, err := os.MkdirTemp("", "gx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, err := net.Listen("unix", filepath.Join(dir, "ctl.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	requests := make(chan controlproto.Request, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		var req controlproto.Request
		_ = json.NewDecoder(c).Decode(&req)
		requests <- req
		_, _ = fmt.Fprintln(c, `{"ok":true}`)
	}()
	sendSessionResize(dir, "s1", 120, 33)
	req := <-requests
	if req.Op != "resize" || req.ID != "s1" || req.Cols != 120 || req.Rows != 33 {
		t.Fatalf("request = %+v", req)
	}
	// A broker that is gone is not an error for the attached session.
	sendSessionResize(t.TempDir(), "s1", 80, 24)
}
