package sandbox

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// auditRing is a bounded in-memory trail of security-relevant broker
// events: credential deliveries and withholds, secret-source errors, and
// OAuth custody events. daemon.log remains the primary record; the ring
// backs the audit.tail control op so `gantry audit` can read events back
// from a running sandbox without touching the host filesystem.
//
// Lines MUST never carry secret material — the trail names secrets, it
// does not quote them. The adversarial-input test
// (TestAuditTrailNeverLeaksSecretMaterial) fuzzes that invariant.
const (
	auditRingCapacity = 256
	auditRingMaxBytes = 1 << 20
	auditLineMaxBytes = 4 << 10
)

type auditRing struct {
	mu    sync.Mutex
	lines []string
	bytes int
}

func (r *auditRing) append(line string) {
	if r == nil {
		return
	}
	line = sanitizeAuditLine(line)
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.lines) > 0 && (len(r.lines) >= auditRingCapacity || r.bytes+len(line) > auditRingMaxBytes) {
		r.bytes -= len(r.lines[0])
		copy(r.lines, r.lines[1:])
		r.lines = r.lines[:len(r.lines)-1]
	}
	r.lines = append(r.lines, line)
	r.bytes += len(line)
}

func (r *auditRing) tail() []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// auditf records a security-relevant event: it lands on the daemon's
// stderr (daemon.log, the primary record) and in the bounded audit ring
// for control-socket readback.
func (br *broker) auditf(format string, a ...any) {
	line := sanitizeAuditLine(fmt.Sprintf(format, a...))
	br.auditMu.Lock()
	defer br.auditMu.Unlock()
	br.audit.append(line)
	fmt.Printf("daemon: %s\n", line)
	br.persistAuditLine(line)
}

// sanitizeAuditLine enforces the audit trail's line-oriented, bounded schema.
// Payload-derived CR/LF/control bytes cannot forge entries, and one request
// cannot retain an arbitrarily large string in memory or on disk.
func sanitizeAuditLine(line string) string {
	line = strings.ToValidUTF8(line, "�")
	var out strings.Builder
	out.Grow(min(len(line), auditLineMaxBytes))
	truncated := false
	for _, r := range line {
		var text string
		switch r {
		case '\n':
			text = `\n`
		case '\r':
			text = `\r`
		case '\t':
			text = `\t`
		default:
			if r < 0x20 || r == 0x7f {
				text = fmt.Sprintf(`\u%04x`, r)
			} else {
				text = string(r)
			}
		}
		if out.Len()+len(text) > auditLineMaxBytes-32 {
			truncated = true
			break
		}
		out.WriteString(text)
	}
	if truncated {
		out.WriteString("…[audit line truncated]")
	}
	return out.String()
}

// auditLogCap bounds the on-disk trail; past it the file is rewritten with
// its trailing half (best-effort — the live ring stays authoritative).
const auditLogCap = 1 << 20

// persistAuditLine appends to <dir>/audit.log so `gantry audit` works after
// the daemon stops. Never fails loudly: disk trouble must not break the
// custody paths that audit.
func (br *broker) persistAuditLine(line string) {
	if br.dir == "" {
		return
	}
	path := filepath.Join(br.dir, "audit.log")
	st, statErr := os.Lstat(path)
	if statErr == nil && (st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular()) {
		return // never follow or block on a pre-planted audit endpoint
	}
	if statErr != nil && !os.IsNotExist(statErr) {
		return
	}
	if statErr == nil && st.Size() > auditLogCap {
		const keep = auditLogCap / 2
		if f, err := os.Open(path); err == nil {
			start := st.Size() - keep
			if start < 0 {
				start = 0
			}
			_, _ = f.Seek(start, io.SeekStart)
			trailing, readErr := io.ReadAll(io.LimitReader(f, keep+1))
			_ = f.Close()
			if readErr == nil {
				if start > 0 {
					if newline := bytes.IndexByte(trailing, '\n'); newline >= 0 {
						trailing = trailing[newline+1:]
					} else {
						trailing = nil // corrupt overlong fragment, not an audit entry
					}
				}
				_ = os.WriteFile(path, trailing, 0o600)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_ = f.Chmod(0o600)
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintln(f, line)
}
