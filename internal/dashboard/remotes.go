package dashboard

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/ejpir/gantry/internal/orgauth"
	"github.com/ejpir/gantry/internal/remote"
)

type remoteSection remote.WatchSnapshot
type remoteSectionMsg struct {
	snapshot   remote.WatchSnapshot
	generation uint64
	removed    bool
}
type remoteCatalogMsg struct{ available []orgauth.AvailableRemote }
type remoteConfigMsg struct{ error string }

// Poll local profile/receipt metadata to adopt TUI adds and login/logout
// without restarting. Each SSE worker has a cancelable generation so messages
// from removed/reconfigured sources cannot resurrect stale rows.
func startRemoteWatches(parent context.Context, send func(tea.Msg)) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var active sync.WaitGroup
		type worker struct {
			profile remote.Profile
			cancel  context.CancelFunc
		}
		workers := make(map[string]worker)
		defer func() {
			for _, w := range workers {
				w.cancel()
			}
			active.Wait()
		}()
		var generation uint64
		var previousCatalog []orgauth.AvailableRemote
		var previousError string
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			profiles, err := remote.List()
			storeError := ""
			if err != nil {
				profiles = nil
				storeError = safeUILine(err.Error())
			}
			if storeError != previousError {
				previousError = storeError
				send(remoteConfigMsg{error: storeError})
			}
			live := make(map[string]bool)
			for _, profile := range profiles {
				live[profile.Name] = true
				if w, ok := workers[profile.Name]; ok && w.profile == profile {
					continue
				}
				if w, ok := workers[profile.Name]; ok {
					w.cancel()
				}
				generation++
				watchCtx, cancel := context.WithCancel(ctx)
				workers[profile.Name] = worker{profile, cancel}
				send(remoteSectionMsg{snapshot: remote.WatchSnapshot{Remote: profile.Name, Error: "connecting"}, generation: generation})
				current := generation
				active.Go(func() { watchRemoteProfile(watchCtx, profile, current, send) })
			}
			for name, w := range workers {
				if !live[name] {
					w.cancel()
					generation++
					send(remoteSectionMsg{snapshot: remote.WatchSnapshot{Remote: name}, generation: generation, removed: true})
					delete(workers, name)
				}
			}
			available, catalogErr := orgauth.AvailableRemotes(orgauth.SessionDir())
			if catalogErr != nil {
				available = nil
			}
			if !reflect.DeepEqual(previousCatalog, available) {
				previousCatalog = available
				send(remoteCatalogMsg{available: available})
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func watchRemoteProfile(ctx context.Context, profile remote.Profile, generation uint64, send func(tea.Msg)) {
	update := func(s remote.WatchSnapshot) {
		if ctx.Err() == nil {
			send(remoteSectionMsg{snapshot: s, generation: generation})
		}
	}
	// Periodically reload credentials, including after a server-side token
	// rotation, so replacing the token file recovers an open dashboard.
	for ctx.Err() == nil {
		token, err := remote.LoadToken(profile.Name)
		if err == nil {
			var client *remote.Client
			client, err = remote.Dial(profile, token)
			if err == nil {
				cycle, cancel := context.WithTimeout(ctx, 30*time.Second)
				client.WatchSandboxes(cycle, update)
				cancel()
				client.Close()
				continue
			}
		}
		update(remote.WatchSnapshot{Remote: profile.Name, Error: err.Error()})
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

type remoteRow struct {
	text, target string
	suggestion   *orgauth.AvailableRemote
}

func (m sandboxTUIModel) remoteRows() []remoteRow {
	names := make([]string, 0, len(m.remotes))
	for name := range m.remotes {
		names = append(names, name)
	}
	sort.Strings(names)
	var rows []remoteRow
	for _, name := range names {
		section := m.remotes[name]
		rows = append(rows, remoteRow{text: "Remote: " + safeUILine(name), target: name})
		if section.Error != "" {
			rows = append(rows, remoteRow{text: "  " + safeUILine(section.Error), target: name})
			continue
		}
		if len(section.Sandboxes) == 0 {
			rows = append(rows, remoteRow{text: "  (no sandboxes)", target: name})
		}
		for _, row := range section.Sandboxes {
			rows = append(rows, remoteRow{text: safeUILine(fmt.Sprintf("  %-24s %-9s %d CPU  %d MiB  %s", row.Name, row.State, row.CPUs, row.MemoryMiB, row.Image)), target: name})
		}
	}
	for _, suggestion := range m.availableRemotes {
		if !time.Now().Before(suggestion.ExpiresAt) {
			continue
		}
		rows = append(rows, remoteRow{text: safeUILine("Available from " + suggestion.Organization + ": " + suggestion.Profile.Name + " — " + suggestion.Profile.URL), suggestion: &suggestion})
	}
	return rows
}

func (m sandboxTUIModel) remoteLines() []string {
	var lines []string
	for _, row := range m.remoteRows() {
		lines = append(lines, row.text)
	}
	return lines
}

func (m sandboxTUIModel) remoteNotice() string {
	if m.remoteConfigError != "" {
		return "remote profiles unavailable · local unaffected (B)"
	}
	var offline []string
	for name, section := range m.remotes {
		if section.Error != "" {
			offline = append(offline, safeUILine(name))
		}
	}
	sort.Strings(offline)
	if len(offline) == 0 {
		return ""
	}
	return "remote unavailable: " + strings.Join(offline, ", ") + " · local unaffected (B)"
}

func (m sandboxTUIModel) renderRemotes(theme tuiTheme, layout tuiDashboardLayout) string {
	lines := m.remoteLines()
	if len(lines) == 0 {
		description := "Press a to add a standalone remote (no organization required), or L to sign in and discover organization remotes."
		if m.remoteConfigError != "" {
			description = "Remote profiles unavailable: " + m.remoteConfigError
		}
		return m.renderTableEmpty(theme, layout, "Remote managers", description)
	}
	start := min(m.remoteScroll, len(lines))
	end := min(len(lines), start+max(1, layout.contentHeight-2))
	visible := []string{"Remotes — a add · t test · d remove · L sign in · enter create/add", ""}
	for i := start; i < end; i++ {
		marker := "  "
		if i == m.remoteCursor {
			marker = "› "
		}
		visible = append(visible, marker+lines[i])
	}
	for i := range visible {
		visible[i] = truncateText(visible[i], max(1, layout.width-4))
	}
	style := lipgloss.NewStyle().Foreground(theme.text).Background(theme.bg).Padding(0, 2).Width(layout.width).Height(layout.contentHeight).MaxHeight(layout.contentHeight)
	return renderSurface(style, theme.text, theme.bg, strings.Join(visible, "\n"))
}
