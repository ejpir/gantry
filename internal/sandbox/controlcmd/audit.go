package controlcmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// PersistedAuditTail reads the bounded on-disk trail without dialing the broker.
// Callers that already know a sandbox is stopped can avoid connection retries.
func PersistedAuditTail(name string) ([]string, error) {
	if !layout.ValidName(name) {
		return nil, fmt.Errorf("invalid sandbox name %q", name)
	}
	path := filepath.Join(layout.Dir(name), "audit.log")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("audit.log must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	const maxPersistedAuditRead = 1 << 20
	if st, statErr := f.Stat(); statErr == nil && st.Size() > maxPersistedAuditRead {
		_, _ = f.Seek(st.Size()-maxPersistedAuditRead, io.SeekStart)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPersistedAuditRead+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPersistedAuditRead {
		b = b[len(b)-maxPersistedAuditRead:]
	}
	// A tail seek can begin mid-line; discard that fragment.
	if len(b) == maxPersistedAuditRead {
		if newline := strings.IndexByte(string(b), '\n'); newline >= 0 {
			b = b[newline+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	const tail = 256
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return lines, nil
}

// AuditTail reads the sandbox daemon's bounded in-memory trail of
// security-relevant events (organization policy decisions, credential
// deliveries and withholds, secret-source errors, OAuth custody events) over
// ctl.sock, falling back to audit.log after shutdown. The trail names secrets
// but never quotes their values.
func AuditTail(name string) ([]string, error) {
	resp, err := controlproto.Call[controlproto.AuditResponse](name, controlproto.Request{
		Op: "audit.tail",
		ID: controlproto.NewRequestID("audit"),
	})
	if err != nil {
		// Daemon down: serve the persisted trail instead of a bare dial
		// error. The ring is authoritative while running; audit.log is its
		// disk tee.
		if lines, ferr := PersistedAuditTail(name); ferr == nil {
			return lines, nil
		}
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("audit.tail: %s", resp.Error)
	}
	return resp.Lines, nil
}
