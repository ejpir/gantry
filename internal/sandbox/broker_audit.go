package sandbox

import (
	"fmt"
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
const auditRingCapacity = 256

type auditRing struct {
	mu    sync.Mutex
	lines []string
}

func (r *auditRing) append(line string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) == auditRingCapacity {
		copy(r.lines, r.lines[1:])
		r.lines = r.lines[:auditRingCapacity-1]
	}
	r.lines = append(r.lines, line)
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
	line := fmt.Sprintf(format, a...)
	br.audit.append(line)
	fmt.Printf("daemon: %s\n", line)
}
