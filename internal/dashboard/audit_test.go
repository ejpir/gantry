package dashboard

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
)

func auditTestModel() sandboxTUIModel {
	m := queryTestModel()
	m.page = tuiAuditPage
	m.auditEvents[0].Decision.Organization = "example-org"
	m.auditEvents[0].Decision.Revision = "revision-1"
	m.auditEvents[0].Decision.Profile = "developer"
	m.auditEvents[0].Decision.Rules = []string{"blocked-tool"}
	m.auditEvents[0].Line = "policy: recorded denied event"
	return m
}

func TestAuditNavigationAndActions(t *testing.T) {
	m := auditTestModel()
	m.setPage(tuiMCPPage)
	m.cyclePage(1)
	if m.page != tuiAuditPage {
		t.Fatal("audit missing from forward tab order")
	}
	m.cyclePage(1)
	if m.page != tuiImagesPage {
		t.Fatal("existing images view lost")
	}
	m.cyclePage(-1)
	if m.page != tuiAuditPage {
		t.Fatal("audit missing from reverse tab order")
	}
	m.setPage(tuiOverviewPage)
	_, _ = m.Update(tea.KeyPressMsg{Code: 'A'})
	if m.page != tuiAuditPage || pageDisplayTitle(m.page) != "Audit" {
		t.Fatal("A did not open Audit")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	if m.auditCursor != 1 {
		t.Fatal("table navigation did not select next audit event")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.dialog != tuiAuditDetailDialog || m.auditDetail == nil || m.auditDetail.Sandbox != "alpha" {
		t.Fatal("enter did not inspect selected event")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.dialog != tuiNoDialog || m.auditDetail != nil {
		t.Fatal("closing details retained the event")
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: 'r'})
	if cmd == nil || !m.refreshing {
		t.Fatal("refresh did not request a new snapshot")
	}
	m.auditEvents = nil
	_, _ = m.Update(tea.KeyPressMsg{Code: 'd'})
	if m.dialog != tuiNoDialog || m.busyAction != "" {
		t.Fatal("empty audit should not open details or mutate a sandbox")
	}
}

func TestAuditSelectionRefreshAndFrozenDetails(t *testing.T) {
	m := auditTestModel()
	m.rememberViewSource()
	m.auditCursor = 0
	key := m.selectedAuditKey()
	m.openAuditDetail()
	original := m.auditDetail.Line
	// Copy all nested provenance: refreshes must not rewrite an open event.
	m.auditEvents[0].Decision.Rules[0] = "changed"
	if m.auditDetail.Decision.Rules[0] != "blocked-tool" {
		t.Fatal("open details alias mutable rules")
	}
	msg := *m.viewSource
	msg.audit = append([]tuiAuditRow{{Sandbox: "Zulu", Line: "new event"}}, msg.audit...)
	_, _ = m.handleRefresh(msg)
	if m.selectedAuditKey() != key || m.auditCursor != 1 || m.auditDetail.Line != original {
		t.Fatal("refresh lost selection or changed open details")
	}
	m.closeDialog()
	m.applySandboxFilter("ALP")
	if len(m.auditEvents) != 1 || m.auditEvents[0].Sandbox != "alpha" {
		t.Fatal("audit did not apply sandbox filter")
	}
	m.applySandboxFilter("")
	if len(m.auditEvents) != 3 {
		t.Fatal("clearing filter did not restore audit rows")
	}
	m.chooseSort("result")
	if auditStatus(m.auditEvents[0]) != "ALLOW" {
		t.Fatal("result sort not applied")
	}
	m.chooseSort("")
	if m.auditEvents[0].Line != "new event" {
		t.Fatal("default did not restore source order")
	}
	// Identical retained events are individually selectable after sorting.
	m.auditEvents = []tuiAuditRow{{Sandbox: "dev", Line: "same", Occurrence: 0}, {Sandbox: "dev", Line: "same", Occurrence: 1}}
	m.auditCursor = 1
	key = m.selectedAuditKey()
	m.auditCursor = 0
	m.restoreAuditSelection(key)
	if m.auditCursor != 1 {
		t.Fatal("duplicate events collapsed onto the first row")
	}
	m.auditEvents = nil
	m.restoreAuditSelection(key)
	if m.auditCursor != 0 {
		t.Fatal("evicted selection was not clamped")
	}
}

func TestAuditRenderingAndMouse(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, width := range []int{24, 40, 60, 86, 120, 200} {
			m := auditTestModel()
			m.dark, m.width, m.height = dark, width, 30
			view := m.View().Content
			if lipgloss.Width(view) > width || lipgloss.Height(view) > m.height {
				t.Fatalf("audit view overflow at width %d", width)
			}
			plain := ansi.Strip(view)
			if !strings.Contains(plain, "DENY") || !strings.Contains(plain, "Zulu") {
				t.Fatalf("audit row missing at width %d:\n%s", width, plain)
			}
			if width >= 120 && (!strings.Contains(plain, "example-org") || !strings.Contains(plain, "revision-1") || !strings.Contains(plain, "blocked-tool")) {
				t.Fatalf("selected policy provenance missing:\n%s", plain)
			}
			clicked := false
			for _, hit := range m.dashboardHits {
				if hit.kind == "table-row" && hit.index == 1 {
					_, _ = m.updateMouseClick(tea.Mouse{X: hit.rect.x, Y: hit.rect.y, Button: tea.MouseLeft})
					clicked = m.auditCursor == 1
					break
				}
			}
			if !clicked {
				t.Fatalf("audit row has no working mouse target at width %d", width)
			}
			m.auditCursor = 0
			m.auditEvents[0].Line = strings.Repeat("long-audit-event ", 250) + "end-marker"
			m.openAuditDetail()
			details := ansi.Strip(m.renderAuditDetailDialog(tuiThemeFor(dark), width-8))
			if !strings.Contains(details, "end-marker") || lipgloss.Width(details) > width-8 {
				t.Fatal("audit details truncated the recorded event or failed to wrap")
			}
			view = m.View().Content
			if lipgloss.Width(view) > width || lipgloss.Height(view) > m.height {
				t.Fatal("audit detail dialog overflowed viewport")
			}
			_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnd})
			if m.dialogScroll <= 0 || m.dialogScroll != m.dialogMaxScroll() {
				t.Fatal("full audit event cannot be scrolled")
			}
		}
	}
	m := auditTestModel()
	m.page, m.width = tuiOverviewPage, 200
	_ = m.View()
	for _, hit := range m.dashboardHits {
		if hit.kind == "page" && hit.page == tuiAuditPage {
			_, _ = m.updateMouseClick(tea.Mouse{X: hit.rect.x, Y: hit.rect.y, Button: tea.MouseLeft})
			if m.page != tuiAuditPage {
				t.Fatal("audit tab click did not navigate")
			}
			return
		}
	}
	t.Fatal("audit tab has no render-produced mouse target")
}

func TestAuditEmptyLoadingAndErrorStates(t *testing.T) {
	m := auditTestModel()
	m.width, m.height = 120, 30
	m.auditEvents = nil
	if !strings.Contains(ansi.Strip(m.View().Content), "No audit events recorded") {
		t.Fatal("empty audit state missing")
	}
	m.loading = true
	if !strings.Contains(ansi.Strip(m.View().Content), "Loading audit trail") {
		t.Fatal("audit loading state missing")
	}
	m.loading = false
	m.auditEvents = []tuiAuditRow{{Sandbox: "failed", Error: "audit read failed"}}
	if got := ansi.Strip(m.View().Content); !strings.Contains(got, "ERROR") || !strings.Contains(got, "audit read failed") || !strings.Contains(got, "1 unavailable") {
		t.Fatalf("audit error hidden: %s", got)
	}
	m.openAuditDetail()
	if !strings.Contains(ansi.Strip(m.renderAuditDetailDialog(tuiThemeFor(m.dark), 72)), "audit read failed") {
		t.Fatal("audit error details missing")
	}
}

type auditSnapshotService struct {
	dashboardapi.Service
	data dashboardapi.Snapshot
}

func (s auditSnapshotService) Snapshot() (dashboardapi.Snapshot, error) { return s.data, nil }

func TestAuditSnapshotSanitizesAllDisplayFields(t *testing.T) {
	bad := "\x1b[2Junsafe\nvalue\x1b]52;c;payload\a"
	d := &dashboardapi.AuditDecision{Effect: bad, Action: bad, Reason: bad, Organization: bad, Revision: bad, Profile: bad, Rules: []string{bad}}
	s := auditSnapshotService{data: dashboardapi.Snapshot{Audit: []tuiAuditRow{{Sandbox: bad, Line: bad, Error: bad, Decision: d}}}}
	msg := refreshSandboxesCmd(s)().(tuiRefreshMsg)
	if len(msg.audit) != 1 {
		t.Fatal("refresh omitted audit data")
	}
	row := msg.audit[0]
	for _, value := range []string{row.Sandbox, row.Line, row.Error, row.Decision.Effect, row.Decision.Action, row.Decision.Reason, row.Decision.Organization, row.Decision.Revision, row.Decision.Profile, row.Decision.Rules[0]} {
		if value != "unsafe value" {
			t.Fatalf("unsafe audit field: %q", value)
		}
	}
	if s.data.Audit[0].Line != bad || s.data.Audit[0].Decision != d || d.Action != bad || d.Rules[0] != bad {
		t.Fatal("sanitization mutated service-owned audit data")
	}
	m := auditTestModel()
	_, _ = m.handleRefresh(msg)
	m.openAuditDetail()
	if strings.Contains(m.View().Content, "\x1b[2J") || strings.Contains(fmt.Sprint(m.auditDetail), "\x1b]52") {
		t.Fatal("audit display retained terminal escape sequences")
	}
}
