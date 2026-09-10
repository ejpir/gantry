package dashboard

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/ejpir/gantry/internal/packetcapture"
)

func queryTestModel() sandboxTUIModel {
	m := modernDashboardTestModel()
	m.sandboxes = []tuiSandbox{
		{Name: "Zulu", State: tuiRunning, Image: "z:latest", Runtime: "gvisor", VCPUs: 10, MemMB: 4096, Net: true, Shares: 10, Ports: 10, TXBytes: 10, RXBytes: 100, DroppedPackets: 10},
		{Name: "alpha", State: tuiStopped, Image: "a:latest", Runtime: "crun", VCPUs: 2, MemMB: 512, Shares: 2, Ports: 2, TXBytes: 2, RXBytes: 2, DroppedPackets: 2},
	}
	m.traffic = []tuiTrafficRow{{Sandbox: "Zulu", Host: "z.test", Protocol: "udp", Port: 100, TXBytes: 10, RXBytes: 100, TXPackets: 9, LastSeen: time.Unix(100, 0)}, {Sandbox: "alpha", Host: "a.test", Protocol: "tcp", Port: 20, Allowed: true, TXBytes: 2, RXBytes: 2, TXPackets: 2, LastSeen: time.Unix(20, 0)}}
	m.rules = []tuiRuleRow{{Sandbox: "Zulu", Action: "deny", Target: "z.test", Proto: "udp", Ports: "443", Source: "rule 1"}, {Sandbox: "alpha", Action: "allow", Target: "a.test", Proto: "tcp", Ports: "80", Source: "rule 2"}}
	m.mounts = []tuiMountRow{{Sandbox: "Zulu", Tag: "z", Host: "/z", Guest: "/z", State: "saved"}, {Sandbox: "alpha", Tag: "a", Host: "/a", Guest: "/a", ReadOnly: true, State: "active"}}
	m.ports = []tuiPortRow{{Sandbox: "Zulu", Bind: "127.0.0.1:9000", Guest: 100, Proto: "udp", State: "saved"}, {Sandbox: "alpha", Bind: "127.0.0.1:8000", Guest: 20, Proto: "tcp", State: "bound"}}
	m.secrets = []tuiSecretRow{{Sandbox: "Zulu", Name: "Z", State: "required"}, {Sandbox: "alpha", Name: "A", State: "loaded"}}
	m.mcpServers = []tuiMCPRow{{Sandbox: "Zulu", Name: "z", Type: "remote", URL: "https://z.test", AuthKind: "bearer", State: "saved"}, {Sandbox: "alpha", Name: "a", Type: "local", Root: "/a", State: "active"}}
	m.images = []tuiImageRow{{Ref: "z:latest", Digest: "z", Arch: "arm64", Size: 10, Created: "2026-01-01T10:00:00Z", InUse: true}, {Ref: "a:latest", Digest: "a", Arch: "amd64", Size: 2, Created: "2026-01-01T10:30:00+01:00"}}
	m.registries = []tuiRegistryRow{{Registry: "z.test", Username: "z", Source: "helper", HasSecret: true}, {Registry: "a.test", Username: "a", Source: "config"}}
	m.packets = []tuiPacketRow{{Sandbox: "Zulu", Sequence: 2, Timestamp: time.Unix(100, 0), Direction: packetcapture.TX, Length: 100, Source: "z", Target: "z", Protocol: "udp", Info: "Z"}, {Sandbox: "alpha", Sequence: 1, Timestamp: time.Unix(20, 0), Direction: packetcapture.RX, Length: 20, Source: "a", Target: "a", Protocol: "tcp", Info: "A", Allowed: true}}
	return m
}

func TestSandboxFilterKeyboardApplyCancelClear(t *testing.T) {
	m := queryTestModel()
	m.page = tuiTrafficPage
	_, _ = m.Update(tea.KeyPressMsg{Code: '/'})
	if m.dialog != tuiSandboxFilterDialog {
		t.Fatal("/ did not open sandbox filter")
	}
	for _, r := range "ALP" {
		_, _ = m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	if len(m.traffic) != 2 || m.dialog != tuiSandboxFilterDialog {
		t.Fatal("typing triggered a page action or applied prematurely")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.sandboxFilter != "ALP" || len(m.traffic) != 1 || m.selectedTraffic().Sandbox != "alpha" {
		t.Fatalf("filter failed: %q %+v", m.sandboxFilter, m.traffic)
	}
	for _, page := range []tuiPage{tuiOverviewPage, tuiSandboxesPage, tuiTrafficPage, tuiRulesPage, tuiMountsPage, tuiPortsPage, tuiSecretsPage, tuiMCPPage, tuiPacketsPage} {
		m.setPage(page)
		if m.pageRowCount(page) != 1 {
			t.Fatalf("page %d did not share filter", page)
		}
	}
	m.setPage(tuiImagesPage)
	if len(m.images) != 2 || len(m.registries) != 2 || !strings.Contains(m.viewQueryLabel(), "host-wide") {
		t.Fatal("sandbox filter hid host-wide resources")
	}
	if len(m.allSandboxes()) != 2 {
		t.Fatal("filter changed packet capture targets")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: '/'})
	m.sandboxFilterInput.SetValue("Zulu")
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.sandboxFilter != "ALP" {
		t.Fatal("escape applied a draft")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: '/'})
	m.sandboxFilterInput.SetValue("")
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(m.sandboxes) != 2 || len(m.traffic) != 2 || len(m.packets) != 2 {
		t.Fatal("clearing filter did not restore source rows immediately")
	}
}

func TestColumnSortNumericSelectionAndRefresh(t *testing.T) {
	m := queryTestModel()
	m.page = tuiTrafficPage
	key := trafficRowKey(*m.selectedTraffic())
	m.chooseSort("tx")
	if m.traffic[0].TXBytes != 2 || m.traffic[1].TXBytes != 10 || trafficRowKey(*m.selectedTraffic()) != key {
		t.Fatal("ascending numeric sort lost selection or sorted lexically")
	}
	m.chooseSort("tx")
	if m.traffic[0].TXBytes != 10 || !m.sorts[tuiTrafficPage].desc || trafficRowKey(*m.selectedTraffic()) != key {
		t.Fatal("reverse sort lost selection")
	}
	original := append([]tuiTrafficRow(nil), m.viewSource.traffic...)
	m.applySandboxFilter("zul")
	msg := *m.viewSource
	msg.traffic = []tuiTrafficRow{original[1], original[0]}
	msg.traffic[1].TXBytes = 99
	_, _ = m.handleRefresh(msg)
	if len(m.traffic) != 1 || m.traffic[0].TXBytes != 99 || trafficRowKey(*m.selectedTraffic()) != key || !m.sorts[tuiTrafficPage].desc {
		t.Fatal("refresh lost filter, ordering, or row identity")
	}
	m.applySandboxFilter("")
	if m.traffic[0].TXBytes != 99 || len(m.traffic) != 2 {
		t.Fatal("clearing filter lost sort")
	}
	m.chooseSort("")
	if m.traffic[0].Sandbox != "alpha" {
		t.Fatal("default order did not restore the latest source order")
	}
	if !reflect.DeepEqual(original[0], queryTestModel().traffic[0]) {
		t.Fatal("sorting mutated source snapshot")
	}
}

func currentSortValues(m sandboxTUIModel, key string) []tuiSortValue {
	var values []tuiSortValue
	switch m.page {
	case tuiOverviewPage, tuiSandboxesPage:
		for _, r := range m.sandboxes {
			values = append(values, sandboxSortValue(r, key))
		}
	case tuiTrafficPage:
		for _, r := range m.traffic {
			values = append(values, trafficSortValue(r, key))
		}
	case tuiRulesPage:
		for _, r := range m.rules {
			values = append(values, ruleSortValue(r, key))
		}
	case tuiMountsPage:
		for _, r := range m.mounts {
			values = append(values, mountSortValue(r, key))
		}
	case tuiPortsPage:
		for _, r := range m.ports {
			values = append(values, portSortValue(r, key))
		}
	case tuiSecretsPage:
		for _, r := range m.secrets {
			values = append(values, secretSortValue(r, key))
		}
	case tuiMCPPage:
		for _, r := range m.mcpServers {
			values = append(values, mcpSortValue(r, key))
		}
	case tuiPacketsPage:
		for _, r := range m.packets {
			values = append(values, packetSortValue(r, key))
		}
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			for _, r := range m.registries {
				values = append(values, registrySortValue(r, key))
			}
		} else {
			for _, r := range m.images {
				values = append(values, imageSortValue(r, key))
			}
		}
	}
	return values
}

func TestEveryViewSortFieldAndIndependentPreferences(t *testing.T) {
	m := queryTestModel()
	for scope := 0; scope <= int(tuiPageCount); scope++ {
		m.imageSection = tuiImageSectionImages
		page := tuiPage(scope)
		if scope == int(tuiPageCount) {
			page = tuiImagesPage
			m.imageSection = tuiImageSectionCredentials
		}
		m.setPage(page)
		for _, column := range m.sortColumns() {
			m.chooseSort(column.id)
			ascending := currentSortValues(m, column.id)
			if len(ascending) != 2 || reflect.DeepEqual(ascending[0], ascending[1]) {
				t.Fatalf("scope=%d field=%s has no working value accessor", scope, column.id)
			}
			m.chooseSort(column.id)
			descending := currentSortValues(m, column.id)
			if !reflect.DeepEqual(ascending[0], descending[1]) || !reflect.DeepEqual(ascending[1], descending[0]) {
				t.Fatalf("scope=%d field=%s did not reverse", scope, column.id)
			}
		}
	}
	for scope, state := range m.sorts {
		if state.column == "" || !state.desc {
			t.Fatalf("scope %d lost independent sort preference", scope)
		}
	}
}

func TestSortedHeadersAndFilterToolbarGeometry(t *testing.T) {
	for _, dark := range []bool{true, false} {
		for _, width := range []int{24, 40, 60, 80, 100, 140, 180} {
			m := queryTestModel()
			m.dark, m.width, m.height = dark, width, 32
			m.applySandboxFilter("a")
			for page := tuiSandboxesPage; page < tuiPageCount; page++ {
				m.setPage(page)
				m.chooseSort(m.sortColumns()[0].id)
				view := m.View().Content
				if lipgloss.Width(view) != width || lipgloss.Height(view) != m.height {
					t.Fatalf("dark=%t width=%d page=%d overflow", dark, width, page)
				}
				lines := strings.Split(ansi.Strip(view), "\n")
				if strings.TrimSpace(lines[tuiMenuHeight-1]) != "" || strings.TrimSpace(lines[m.headerHeight()-1]) != "" {
					t.Fatal("filter toolbar is not separated above and below")
				}
				if !strings.Contains(lines[tuiMenuHeight], "Sandbox filter:") {
					t.Fatal("filter is still cramped under navigation")
				}
				for _, target := range m.dashboardHits {
					r := target.rect
					if r.x < 0 || r.y < 0 || r.x+r.w > width || r.y+r.h > m.height {
						t.Fatalf("offscreen target %+v", target)
					}
					got, ok := m.dashboardHitAt(m.dashboardLayout(), r.x+r.w/2, r.y+r.h/2)
					if !ok || got != target {
						t.Fatalf("target mismatch %+v -> %+v", target, got)
					}
				}
			}
		}
	}
}

func TestClickSortHeaderAndKeyboardPicker(t *testing.T) {
	m := queryTestModel()
	m.page = tuiTrafficPage
	_ = m.View()
	var target tuiHitTarget
	for _, hit := range m.dashboardHits {
		if hit.kind == "sort-column" && hit.action == "tx" {
			target = hit
		}
	}
	if target.rect.w == 0 {
		t.Fatal("TX header is not clickable")
	}
	_, _ = m.updateMouseClick(tea.Mouse{X: target.rect.x + 1, Y: target.rect.y, Button: tea.MouseLeft})
	if m.sorts[tuiTrafficPage].column != "tx" || m.traffic[0].TXBytes != 2 {
		t.Fatal("header click did not sort")
	}
	header := m.renderSortableTableHeader(tuiThemeFor(m.dark), m.page, m.width-4)
	if !strings.Contains(header, "▲") {
		t.Fatal("sort indicator missing")
	}
	// The sort header must not underline either its text or its padding.
	if strings.Contains(header, "[4;") || strings.Contains(header, ";4;") || strings.Contains(header, "[4m") {
		t.Fatal("sort underline was reintroduced")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: 'S', Text: "S"})
	if m.dialog != tuiSortDialog {
		t.Fatal("S did not open picker")
	}
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyHome})
	_, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.dialog != tuiNoDialog || m.sorts[tuiTrafficPage].column != "" {
		t.Fatal("picker did not restore default order")
	}
}

func TestPacketFilteringKeepsChronologicalBoundedSource(t *testing.T) {
	m := queryTestModel()
	m.page = tuiPacketsPage
	m.applySandboxFilter("Zulu")
	m.chooseSort("length")
	key := m.selectedPacketKey()
	_, _ = m.handlePacketCapture(tuiPacketCaptureMsg{rows: []tuiPacketRow{{Sandbox: "alpha", Sequence: 3, Timestamp: time.Unix(200, 0), Length: 1}, {Sandbox: "Zulu", Sequence: 4, Timestamp: time.Unix(300, 0), Length: 2}}})
	if len(m.packetSource) != 4 || len(m.packets) != 2 || m.packets[0].Length != 2 || m.selectedPacketKey() != key {
		t.Fatal("live packet capture lost source, sort, or selection")
	}
	m.applySandboxFilter("")
	if len(m.packets) != 4 {
		t.Fatal("hidden captured packets were discarded")
	}
	m.applySandboxFilter("unmatched")
	var rows []tuiPacketRow
	for i := 0; i < tuiMaxPacketRows+20; i++ {
		rows = append(rows, tuiPacketRow{Sandbox: "alpha", Sequence: uint64(i + 10), Timestamp: time.Unix(int64(i+400), 0)})
	}
	_, _ = m.handlePacketCapture(tuiPacketCaptureMsg{rows: rows})
	if len(m.packetSource) != tuiMaxPacketRows || len(m.packets) != 0 {
		t.Fatal("packet source is not bounded independently of filter")
	}
	m.applySandboxFilter("")
	if len(m.packets) != tuiMaxPacketRows {
		t.Fatal("clear did not restore retained packets")
	}
}

func TestFilteredOutRowsCannotBecomeActionTargets(t *testing.T) {
	m := queryTestModel()
	m.applySandboxFilter("absent")
	for _, page := range []tuiPage{tuiTrafficPage, tuiRulesPage, tuiMountsPage, tuiPortsPage, tuiSecretsPage, tuiMCPPage, tuiPacketsPage} {
		m.setPage(page)
		view := m.View().Content
		if !strings.Contains(ansi.Strip(view), "No matching rows") {
			t.Fatalf("page %d gives misleading empty state", page)
		}
		for _, hit := range m.dashboardHits {
			if hit.kind == "table-row" || hit.kind == "sort-column" {
				t.Fatalf("phantom data target %+v", hit)
			}
		}
	}
	if m.selectedTraffic() != nil || m.selectedRule() != nil || m.selectedMount() != nil || m.selectedPort() != nil || m.selectedSecret() != nil || m.selectedMCPServer() != nil {
		t.Fatal("actions can still target hidden rows")
	}
}

func TestSortUsesFullNumericAndChronologicalValues(t *testing.T) {
	m := queryTestModel()
	m.page = tuiTrafficPage
	m.traffic[0].TXBytes = ^uint64(0)
	m.traffic[1].TXBytes = 100
	m.chooseSort("tx")
	if m.traffic[0].TXBytes != 100 {
		t.Fatal("large numeric comparison overflowed")
	}
	m.setPage(tuiImagesPage)
	m.chooseSort("created")
	if m.images[0].Ref != "a:latest" {
		t.Fatal("timestamps sorted as strings instead of instants")
	}
	for _, height := range []int{7, 8, 10, 12} {
		m.height, m.width = height, 40
		m.applySandboxFilter(fmt.Sprint(height))
		if lipgloss.Height(m.View().Content) != height {
			t.Fatalf("short filtered terminal overflow: %d", height)
		}
	}
}
