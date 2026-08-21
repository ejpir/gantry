package controlcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// persistedAudit reads the daemon's on-disk audit tee (<dir>/audit.log).
func persistedAudit(name string) ([]string, error) {
	if !layout.ValidName(name) {
		return nil, fmt.Errorf("invalid sandbox name %q", name)
	}
	b, err := os.ReadFile(filepath.Join(layout.Dir(name), "audit.log"))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	const tail = 256
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return lines, nil
}

// AuditTail reads the sandbox daemon's bounded in-memory trail of
// security-relevant events (credential deliveries and withholds, secret
// source errors, OAuth custody events) over ctl.sock. The trail names
// secrets but never quotes their values.
func AuditTail(name string) ([]string, error) {
	resp, err := controlproto.Call[controlproto.AuditResponse](name, controlproto.Request{
		Op: "audit.tail",
		ID: controlproto.NewRequestID("audit"),
	})
	if err != nil {
		// Daemon down: serve the persisted trail instead of a bare dial
		// error. The ring is authoritative while running; audit.log is its
		// disk tee.
		if lines, ferr := persistedAudit(name); ferr == nil {
			return lines, nil
		}
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("audit.tail: %s", resp.Error)
	}
	return resp.Lines, nil
}
