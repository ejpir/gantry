package dashboardsvc

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
)

func loadDashboardAudit(sandbox dashboardapi.Sandbox) []dashboardapi.AuditEvent {
	var entries []controlcmd.AuditEntry
	var err error
	if sandbox.State == dashboardapi.Stopped {
		entries, err = controlcmd.PersistedAuditEntries(sandbox.Name)
		// A never-started sandbox normally has no trail. Do not turn that
		// into an error row, but retain errors for unreadable/invalid logs.
		if os.IsNotExist(err) {
			return nil
		}
	} else {
		entries, err = controlcmd.AuditEntries(sandbox.Name)
	}
	if err != nil {
		return []dashboardapi.AuditEvent{{Sandbox: sandbox.Name, Error: err.Error()}}
	}
	lines := make([]string, len(entries))
	times := make([]time.Time, len(entries))
	for i, entry := range entries {
		lines[i], times[i] = entry.Line, entry.Time
	}
	return dashboardAuditRows(sandbox.Name, lines, times)
}

// dashboardAuditRows projects the trail, newest first. times is parallel to
// lines when known; a nil or mismatched slice leaves every time zero.
func dashboardAuditRows(name string, lines []string, times []time.Time) []dashboardapi.AuditEvent {
	if len(times) != len(lines) {
		times = nil
	}
	// Bound even legacy/manually edited logs; the daemon normally enforces
	// these limits before writing. Never parse oversized JSON for display.
	const maxEvents, maxLineBytes = 256, 4 << 10
	if len(lines) > maxEvents {
		if times != nil {
			times = times[len(times)-maxEvents:]
		}
		lines = lines[len(lines)-maxEvents:]
	}
	rows := make([]dashboardapi.AuditEvent, 0, len(lines))
	occurrences := make(map[string]int)
	// The source is oldest first. There is no cross-sandbox event clock;
	// preserve sandbox grouping and show newest first within each group.
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if len(line) > maxLineBytes {
			line = strings.ToValidUTF8(line[:maxLineBytes], "�") + "…[audit line truncated]"
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		row := dashboardapi.AuditEvent{Sandbox: name, Line: line, Occurrence: occurrences[line]}
		if times != nil {
			row.Time = times[i]
		}
		occurrences[line]++
		if raw, ok := strings.CutPrefix(line, "policy: "); ok {
			var decision dashboardapi.AuditDecision
			if err := json.Unmarshal([]byte(raw), &decision); err == nil &&
				(decision.Effect == "allow" || decision.Effect == "deny") && decision.Action != "" {
				row.Decision = &decision
			}
		}
		// Truncated, malformed and unrecognized entries remain visible as
		// ordinary events, rather than being dropped or assigned an effect.
		rows = append(rows, row)
	}
	return rows
}
