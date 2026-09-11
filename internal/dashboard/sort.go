package dashboard

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

type tuiSortState struct {
	column string
	desc   bool
}

type tuiSortColumn struct {
	id, label, headers string
}

type tuiSortValue struct {
	text   string
	number uint64
	at     time.Time
}

func sortText(v string) tuiSortValue    { return tuiSortValue{text: strings.ToLower(v)} }
func sortNumber(v uint64) tuiSortValue  { return tuiSortValue{number: v} }
func sortTime(v time.Time) tuiSortValue { return tuiSortValue{at: v} }
func sortBool(v bool) tuiSortValue {
	if v {
		return sortNumber(1)
	}
	return sortNumber(0)
}

func sortRows[T any](rows []T, state tuiSortState, value func(T, string) tuiSortValue) {
	if state.column == "" {
		return
	}
	slices.SortStableFunc(rows, func(a, b T) int {
		x, y := value(a, state.column), value(b, state.column)
		result := cmp.Compare(x.text, y.text)
		if result == 0 {
			result = cmp.Compare(x.number, y.number)
		}
		if result == 0 {
			result = x.at.Compare(y.at)
		}
		if state.desc {
			result = -result
		}
		return result
	})
}

func (m sandboxTUIModel) sortScope() int {
	if m.page == tuiImagesPage && m.imageSection == tuiImageSectionCredentials {
		return int(tuiPageCount)
	}
	return int(m.page)
}

func (m sandboxTUIModel) sortColumns() []tuiSortColumn {
	switch m.page {
	case tuiTrafficPage:
		return []tuiSortColumn{{"status", "Status", "STATUS"}, {"sandbox", "Sandbox", "SANDBOX"}, {"host", "Host / destination", "HOST / DESTINATION|HOST"}, {"proto", "Protocol", "PROTO"}, {"tx", "TX bytes", "↑ TX"}, {"rx", "RX bytes", "↓ RX"}, {"packets", "Packets", "PACKETS"}, {"last", "Last seen", "LAST"}, {"port", "Port", ""}}
	case tuiRulesPage:
		return []tuiSortColumn{{"action", "Action", "ACTION"}, {"sandbox", "Sandbox", "SANDBOX"}, {"target", "Target", "TARGET"}, {"proto", "Protocol", "PROTO"}, {"ports", "Ports", "PORTS"}}
	case tuiMountsPage:
		return []tuiSortColumn{{"mode", "Mode", "MODE"}, {"state", "State", "STATE"}, {"sandbox", "Sandbox", "SANDBOX"}, {"tag", "Tag", "TAG"}, {"host", "Host path", "HOST PATH"}, {"guest", "Container path", "CONTAINER"}}
	case tuiPortsPage:
		return []tuiSortColumn{{"state", "State", "STATE"}, {"sandbox", "Sandbox", "SANDBOX"}, {"bind", "Host bind", "HOST BIND|BIND"}, {"guest", "Guest port", "GUEST"}, {"proto", "Protocol", "PROTO"}}
	case tuiSecretsPage:
		return []tuiSortColumn{{"sandbox", "Sandbox", "SANDBOX"}, {"name", "Name", "NAME"}, {"state", "State", "STATE"}}
	case tuiMCPPage:
		return []tuiSortColumn{{"state", "State", "STATE"}, {"sandbox", "Sandbox", "SANDBOX"}, {"name", "Server", "SERVER"}, {"type", "Type", "TYPE"}, {"endpoint", "Endpoint / root", "ENDPOINT / ROOT|ENDPOINT"}, {"auth", "Authentication", "AUTH"}}
	case tuiPacketsPage:
		return []tuiSortColumn{{"time", "Time", "TIME"}, {"sandbox", "Sandbox", "SANDBOX|VM"}, {"direction", "Direction", "DIR|D"}, {"source", "Source", "SOURCE"}, {"target", "Destination", "DESTINATION|DEST"}, {"proto", "Protocol", "PROTO"}, {"length", "Length", "LEN"}, {"info", "Info", "INFO"}, {"status", "Decision", ""}}
	case tuiImagesPage:
		if m.imageSection == tuiImageSectionCredentials {
			return []tuiSortColumn{{"registry", "Registry", "REGISTRY"}, {"username", "Username", "USERNAME"}, {"source", "Source", "SOURCE"}, {"secret", "Credential present", "SECRET"}}
		}
		return []tuiSortColumn{{"ref", "Image reference", "REF|IMAGE"}, {"digest", "Digest", "DIGEST"}, {"arch", "Architecture", "ARCH"}, {"size", "Size", "SIZE"}, {"created", "Created", "CREATED"}, {"used", "In use", ""}}
	default:
		return []tuiSortColumn{{"name", "Sandbox name", ""}, {"state", "State", ""}, {"image", "Image", ""}, {"runtime", "Runtime", ""}, {"cpu", "vCPUs", ""}, {"memory", "Memory", ""}, {"tx", "TX bytes", ""}, {"rx", "RX bytes", ""}, {"blocked", "Blocked packets", ""}, {"mounts", "Mounts", ""}, {"ports", "Published ports", ""}}
	}
}

func sandboxSortValue(r tuiSandbox, key string) tuiSortValue {
	switch key {
	case "name":
		return sortText(r.Name)
	case "state":
		return sortText(string(r.State))
	case "image":
		return sortText(r.Image)
	case "runtime":
		return sortText(r.Runtime)
	case "cpu":
		return sortNumber(uint64(maxInt(1, r.DisplayCPUs())))
	case "memory":
		return sortNumber(uint64(r.DisplayMemoryMiB()))
	case "tx":
		return sortNumber(r.TXBytes)
	case "rx":
		return sortNumber(r.RXBytes)
	case "blocked":
		return sortNumber(r.DroppedPackets)
	case "mounts":
		return sortNumber(uint64(maxInt(0, r.Shares)))
	case "ports":
		return sortNumber(uint64(maxInt(0, r.Ports)))
	}
	return tuiSortValue{}
}
func trafficSortValue(r tuiTrafficRow, key string) tuiSortValue {
	switch key {
	case "sandbox":
		return sortText(r.Sandbox)
	case "status":
		if r.Allowed {
			return sortText("allow")
		}
		return sortText("block")
	case "host":
		return sortText(defaultText(r.Host, r.Address))
	case "proto":
		return sortText(r.Protocol)
	case "tx":
		return sortNumber(r.TXBytes)
	case "rx":
		return sortNumber(r.RXBytes)
	case "packets":
		return sortNumber(r.TXPackets + r.RXPackets)
	case "last":
		return sortTime(r.LastSeen)
	case "port":
		return sortNumber(uint64(r.Port))
	}
	return tuiSortValue{}
}
func ruleSortValue(r tuiRuleRow, key string) tuiSortValue {
	switch key {
	case "sandbox":
		return sortText(r.Sandbox)
	case "action":
		return sortText(r.Action)
	case "target":
		return sortText(r.Target)
	case "proto":
		return sortText(r.Proto)
	case "ports":
		return sortText(r.Ports)
	}
	return tuiSortValue{}
}
func mountSortValue(r tuiMountRow, key string) tuiSortValue {
	switch key {
	case "sandbox":
		return sortText(r.Sandbox)
	case "mode":
		if r.Error != "" {
			return sortText("err")
		}
		if r.ReadOnly {
			return sortText("ro")
		}
		return sortText("rw")
	case "state":
		if r.Error != "" {
			return sortText("error")
		}
		return sortText(defaultText(r.State, "active"))
	case "tag":
		return sortText(r.Tag)
	case "host":
		return sortText(defaultText(r.Error, r.Host))
	case "guest":
		return sortText(r.Guest)
	}
	return tuiSortValue{}
}
func portSortValue(r tuiPortRow, key string) tuiSortValue {
	switch key {
	case "sandbox":
		return sortText(r.Sandbox)
	case "state":
		if r.Error != "" {
			return sortText("error")
		}
		return sortText(r.State)
	case "bind":
		return sortText(defaultText(r.Error, r.Bind))
	case "guest":
		return sortNumber(uint64(maxInt(0, r.Guest)))
	case "proto":
		return sortText(r.Proto)
	}
	return tuiSortValue{}
}
func secretSortValue(r tuiSecretRow, key string) tuiSortValue {
	switch key {
	case "sandbox":
		return sortText(r.Sandbox)
	case "name":
		return sortText(r.Name)
	case "state":
		return sortText(r.State)
	}
	return tuiSortValue{}
}
func mcpSortValue(r tuiMCPRow, key string) tuiSortValue {
	switch key {
	case "sandbox":
		return sortText(r.Sandbox)
	case "name":
		return sortText(r.Name)
	case "state":
		if r.Error != "" {
			return sortText("error")
		}
		return sortText(r.State)
	case "type":
		return sortText(r.Type)
	case "endpoint":
		if r.Error != "" {
			return sortText(r.Error)
		}
		if r.Type == "local" {
			return sortText(r.Root)
		}
		return sortText(r.URL)
	case "auth":
		return sortText(defaultText(r.AuthKind, "none"))
	}
	return tuiSortValue{}
}
func packetSortValue(r tuiPacketRow, key string) tuiSortValue {
	switch key {
	case "sandbox":
		return sortText(r.Sandbox)
	case "time":
		return sortTime(r.Timestamp)
	case "direction":
		return sortText(fmt.Sprint(r.Direction))
	case "source":
		return sortText(r.Source)
	case "target":
		return sortText(r.Target)
	case "proto":
		return sortText(r.Protocol)
	case "length":
		return sortNumber(uint64(maxInt(0, r.Length)))
	case "info":
		return sortText(r.Info)
	case "status":
		if r.Allowed {
			return sortText("allow")
		}
		return sortText("block")
	}
	return tuiSortValue{}
}
func imageSortValue(r tuiImageRow, key string) tuiSortValue {
	switch key {
	case "ref":
		return sortText(r.Ref)
	case "digest":
		return sortText(r.Digest)
	case "arch":
		return sortText(r.Arch)
	case "size":
		return sortNumber(uint64(max(int64(0), r.Size)))
	case "used":
		return sortBool(r.InUse)
	case "created":
		at, _ := time.Parse(time.RFC3339, r.Created)
		return sortTime(at)
	}
	return tuiSortValue{}
}
func registrySortValue(r tuiRegistryRow, key string) tuiSortValue {
	switch key {
	case "registry":
		return sortText(r.Registry)
	case "username":
		return sortText(defaultText(r.Username, "(anonymous)"))
	case "source":
		return sortText(r.Source)
	case "secret":
		return sortBool(r.HasSecret)
	}
	return tuiSortValue{}
}

type tuiSortHeader struct {
	column   tuiSortColumn
	x, width int
}

// Measure existing responsive headers rather than duplicating their column
// widths. Partial/composite headers still have all fields in the S picker.
func (m sandboxTUIModel) sortHeaderCells(width int) []tuiSortHeader {
	if m.page == tuiOverviewPage || m.page == tuiSandboxesPage {
		return nil
	}
	plain := ansi.Strip(truncateANSI(m.renderTableHeader(tuiThemeFor(m.dark), m.page, width), width))
	var cells []tuiSortHeader
	for _, column := range m.sortColumns() {
		if column.headers == "" {
			continue
		}
		for _, label := range strings.Split(column.headers, "|") {
			start := strings.Index(plain, label)
			if start < 0 {
				continue
			}
			end := start + len(label)
			if (start > 0 && plain[start-1] != ' ') || (end < len(plain) && plain[end] != ' ') {
				continue
			}
			cells = append(cells, tuiSortHeader{column: column, x: lipgloss.Width(plain[:start])})
			break
		}
	}
	slices.SortFunc(cells, func(a, b tuiSortHeader) int { return cmp.Compare(a.x, b.x) })
	for i := range cells {
		end := width
		if i+1 < len(cells) {
			end = cells[i+1].x
		}
		cells[i].width = end - cells[i].x
	}
	return cells
}

func (m sandboxTUIModel) renderSortableTableHeader(theme tuiTheme, page tuiPage, width int) string {
	plain := ansi.Strip(truncateANSI(m.renderTableHeader(theme, page, width), width))
	cells := m.sortHeaderCells(width)
	state := m.sorts[m.sortScope()]
	muted := lipgloss.NewStyle().Bold(true).Foreground(theme.muted)
	if len(cells) == 0 {
		return muted.Render(plain)
	}
	line := muted.Render(ansi.Cut(plain, 0, cells[0].x))
	for _, cell := range cells {
		text := strings.TrimSpace(ansi.Cut(plain, cell.x, cell.x+cell.width))
		style := muted
		if cell.column.id == state.column {
			arrow := " ▲"
			if state.desc {
				arrow = " ▼"
			}
			text = truncateText(text, maxInt(1, cell.width-3)) + arrow
			style = style.Foreground(theme.accent)
		}
		line += style.Render(tableCell(text, cell.width))
	}
	return truncateANSI(line, width)
}

func (m *sandboxTUIModel) chooseSort(column string) {
	if column != "" {
		valid := false
		for _, c := range m.sortColumns() {
			valid = valid || c.id == column
		}
		if !valid {
			return
		}
	}
	m.rememberViewSource()
	state := &m.sorts[m.sortScope()]
	if column == "" {
		*state = tuiSortState{}
	} else if state.column == column {
		state.desc = !state.desc
	} else {
		*state = tuiSortState{column: column}
	}
	m.rebuildView(false)
}
