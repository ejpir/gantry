package controlcmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// AuditEntry is one audit event and when it was recorded. Time is zero for
// events written before the trail carried timestamps.
type AuditEntry struct {
	Time time.Time
	Line string
}

// PersistedAuditTail reads the bounded on-disk trail without dialing the broker.
// Callers that already know a sandbox is stopped can avoid connection retries.
func PersistedAuditTail(name string) ([]string, error) {
	entries, err := PersistedAuditEntries(name)
	return auditLines(entries), err
}

// PersistedAuditEntries is PersistedAuditTail with each event's record time.
func PersistedAuditEntries(name string) ([]AuditEntry, error) {
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
	entries := make([]AuditEntry, 0, len(lines))
	for _, record := range lines {
		at, line := controlproto.ParseAuditRecord(record)
		entries = append(entries, AuditEntry{Time: at, Line: line})
	}
	return entries, nil
}

func auditLines(entries []AuditEntry) []string {
	if entries == nil {
		return nil
	}
	lines := make([]string, len(entries))
	for i, entry := range entries {
		lines[i] = entry.Line
	}
	return lines
}

// AuditTail reads the sandbox daemon's bounded in-memory trail of
// security-relevant events (organization policy decisions, credential
// deliveries and withholds, secret-source errors, OAuth custody events) over
// ctl.sock, falling back to audit.log after shutdown. The trail names secrets
// but never quotes their values.
func AuditTail(name string) ([]string, error) {
	entries, err := AuditEntries(name)
	return auditLines(entries), err
}

// AuditEntries is AuditTail with each event's record time. Daemons that
// predate timestamps report zero times.
func AuditEntries(name string) ([]AuditEntry, error) {
	resp, err := controlproto.Call[controlproto.AuditResponse](name, controlproto.Request{
		Op: "audit.tail",
		ID: controlproto.NewRequestID("audit"),
	})
	if err != nil {
		// Daemon down: serve the persisted trail instead of a bare dial
		// error. The ring is authoritative while running; audit.log is its
		// disk tee.
		if entries, ferr := PersistedAuditEntries(name); ferr == nil {
			return entries, nil
		}
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("audit.tail: %s", resp.Error)
	}
	if resp.Lines == nil {
		return nil, nil
	}
	entries := make([]AuditEntry, len(resp.Lines))
	for i, line := range resp.Lines {
		entries[i].Line = line
		// Times is parallel to Lines; a mismatched length is ignored rather
		// than attributing a time to the wrong event.
		if len(resp.Times) == len(resp.Lines) {
			entries[i].Time = resp.Times[i]
		}
	}
	return entries, nil
}
