package dashboard

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

func auditRowKey(row tuiAuditRow) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", row.Remote, row.Sandbox, row.Line, row.Error, row.Occurrence)
}

func (m sandboxTUIModel) selectedAuditKey() string {
	if m.auditCursor < 0 || m.auditCursor >= len(m.auditEvents) {
		return ""
	}
	return auditRowKey(m.auditEvents[m.auditCursor])
}

func (m *sandboxTUIModel) restoreAuditSelection(key string) {
	index := m.auditCursor
	if key != "" {
		index = 0
		for i, row := range m.auditEvents {
			if auditRowKey(row) == key {
				index = i
				break
			}
		}
	}
	m.tuiSelectionState.setTableCursor(tuiAuditSelection, index, len(m.auditEvents))
}

func (m *sandboxTUIModel) openAuditDetail() {
	if m.auditCursor < 0 || m.auditCursor >= len(m.auditEvents) {
		return
	}
	row := m.auditEvents[m.auditCursor]
	if row.Decision != nil {
		d := *row.Decision
		d.Rules = append([]string(nil), d.Rules...)
		row.Decision = &d
	}
	m.auditDetail = &row
	m.tuiDialogState.open(tuiAuditDetailDialog)
}

func auditStatus(row tuiAuditRow) string {
	if row.Error != "" {
		return "ERROR"
	}
	if row.Decision != nil {
		switch row.Decision.Effect {
		case "allow":
			return "ALLOW"
		case "deny":
			return "DENY"
		}
	}
	return "EVENT"
}

func auditAction(row tuiAuditRow) string {
	if row.Error != "" {
		return "audit unavailable"
	}
	if row.Decision != nil {
		return row.Decision.Action
	}
	return "event"
}

func auditMessage(row tuiAuditRow) string {
	if row.Error != "" {
		return row.Error
	}
	if row.Decision != nil {
		return row.Decision.Reason
	}
	return row.Line
}

func auditSortValue(row tuiAuditRow, column string) tuiSortValue {
	switch column {
	case "sandbox":
		return sortText(sourceDisplayName(row.Sandbox, row.Remote))
	case "result":
		return sortText(auditStatus(row))
	case "action":
		return sortText(auditAction(row))
	case "message":
		return sortText(auditMessage(row))
	}
	return tuiSortValue{}
}

func renderAuditStatus(theme tuiTheme, row tuiAuditRow) string {
	color := theme.secondary
	switch auditStatus(row) {
	case "ALLOW":
		color = theme.success
	case "DENY", "ERROR":
		color = theme.error
	}
	return lipgloss.NewStyle().Bold(true).Foreground(color).Render(auditStatus(row))
}

func (m sandboxTUIModel) renderAuditView(theme tuiTheme, layout tuiDashboardLayout) string {
	return m.renderStandardTable(theme, layout, tuiAuditPage, "Loading audit trail…", "No audit events recorded", "Policy and credential events appear here; stopped sandboxes use audit.log.")
}

func (m sandboxTUIModel) renderAuditHeader(theme tuiTheme, width int) string {
	var line string
	switch {
	case width >= 86:
		line = tableCell("RESULT", 8) + " " + tableCell("SANDBOX", 14) + " " + tableCell("ACTION", 22) + " " + tableCell("DETAIL", width-47)
	case width >= 56:
		line = tableCell("RESULT", 6) + " " + tableCell("SANDBOX", 12) + " " + tableCell("DETAIL", width-20)
	default:
		line = "AUDIT EVENT"
	}
	return lipgloss.NewStyle().Bold(true).Foreground(theme.muted).Render(truncateANSI(line, width))
}

func (m sandboxTUIModel) renderAuditRow(theme tuiTheme, row tuiAuditRow, width int) string {
	status := renderAuditStatus(theme, row)
	message := auditMessage(row)
	switch {
	case width >= 86:
		return tableCell(status, 8) + " " + tableCell(sourceDisplayName(row.Sandbox, row.Remote), 14) + " " + tableCell(auditAction(row), 22) + " " + tableCell(message, width-47)
	case width >= 56:
		if row.Decision != nil {
			message = row.Decision.Action + " · " + message
		}
		return tableCell(status, 6) + " " + tableCell(sourceDisplayName(row.Sandbox, row.Remote), 12) + " " + tableCell(message, width-20)
	default:
		return truncateANSI(status+" "+sourceDisplayName(row.Sandbox, row.Remote)+" · "+auditAction(row)+" · "+message, width)
	}
}

func (m sandboxTUIModel) renderAuditDetail(theme tuiTheme, width int) []string {
	if m.auditCursor < 0 || m.auditCursor >= len(m.auditEvents) || m.tableDetailHeight() == 0 {
		return nil
	}
	row := m.auditEvents[m.auditCursor]
	text := lipgloss.NewStyle().Foreground(theme.secondary)
	muted := lipgloss.NewStyle().Foreground(theme.muted)
	lines := []string{
		m.renderTableSeparator(theme, width),
		renderAuditStatus(theme, row) + "  " + text.Bold(true).Render(sourceDisplayName(row.Sandbox, row.Remote)+" · "+auditAction(row)),
		text.Render(auditMessage(row)),
	}
	if row.Decision != nil {
		d := row.Decision
		lines = append(lines,
			muted.Render("org "+d.Organization+" · revision "+d.Revision+" · profile "+d.Profile),
			muted.Render("rules "+defaultText(strings.Join(d.Rules, ", "), "none")+" · enter details"))
	} else {
		lines = append(lines, muted.Render("Newest first per sandbox · live trail with persisted fallback"), muted.Render("enter details · r refresh · read-only, bounded history"))
	}
	return lines
}

func (m sandboxTUIModel) renderAuditDetailDialog(theme tuiTheme, width int) string {
	lines := []string{m.dialogHeader(theme, "Audit event", width), ""}
	row := m.auditDetail
	if row == nil {
		return strings.Join(lines, "\n") + "No event selected."
	}
	field := func(label, value string) {
		lines = append(lines, lipgloss.NewStyle().Foreground(theme.secondary).Render(
			lipgloss.Wrap(label+": "+defaultText(safeUILine(value), "—"), width, "")))
	}
	field("Sandbox", sourceDisplayName(row.Sandbox, row.Remote))
	field("Result", auditStatus(*row))
	if row.Decision != nil {
		d := row.Decision
		field("Action", d.Action)
		field("Reason", d.Reason)
		field("Organization", d.Organization)
		field("Revision", d.Revision)
		field("Profile", d.Profile)
		field("Rules", strings.Join(d.Rules, ", "))
	}
	lines = append(lines, "")
	if row.Error != "" {
		field("Audit unavailable", row.Error)
	} else {
		field("Recorded event", row.Line)
	}
	lines = append(lines, "", lipgloss.NewStyle().Foreground(theme.muted).Render(lipgloss.Wrap(
		"Bounded, best-effort history; not a compliance archive. Events have no timestamps. ↑/↓ scroll · c copy · esc close", width, "")))
	return strings.Join(lines, "\n")
}
