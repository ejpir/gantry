package dashboardsvc

import (
	"encoding/json"
	"os"
	"strings"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/sandbox/controlcmd"
)

func loadDashboardAudit(sandbox dashboardapi.Sandbox) []dashboardapi.AuditEvent {
	var lines []string
	var err error
	if sandbox.State == dashboardapi.Stopped {
		lines, err = controlcmd.PersistedAuditTail(sandbox.Name)
		// A never-started sandbox normally has no trail. Do not turn that
		// into an error row, but retain errors for unreadable/invalid logs.
		if os.IsNotExist(err) {
			return nil
		}
	} else {
		lines, err = controlcmd.AuditTail(sandbox.Name)
	}
	if err != nil {
		return []dashboardapi.AuditEvent{{Sandbox: sandbox.Name, Error: err.Error()}}
	}
	return dashboardAuditRows(sandbox.Name, lines)
}

func dashboardAuditRows(name string, lines []string) []dashboardapi.AuditEvent {
	// Bound even legacy/manually edited logs; the daemon normally enforces
	// these limits before writing. Never parse oversized JSON for display.
	const maxEvents, maxLineBytes = 256, 4 << 10
	if len(lines) > maxEvents {
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
