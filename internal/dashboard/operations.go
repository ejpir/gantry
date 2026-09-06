package dashboard

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	dashboardapi "github.com/ejpir/gantry/internal/dashboard/api"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"

	tea "charm.land/bubbletea/v2"
)

func runTUIProcessCmd(group *dashboardOperations, service dashboardapi.Service, action, name string, argv []string, interactive bool) tea.Cmd {
	cmd, err := service.Command(group.ctx, argv...)
	if err != nil {
		return func() tea.Msg { return tuiProcessDoneMsg{action: action, name: name, err: err} }
	}
	if interactive {
		return tea.ExecProcess(cmd, func(err error) tea.Msg {
			msg := tuiProcessDoneMsg{action: action, name: name}
			if err != nil {
				msg.output = err.Error()
				// Preserve the session's exit status as a warning rather than an
				// action failure; the TUI and terminal handoff both succeeded.
				if _, ok := err.(*exec.ExitError); !ok {
					msg.err = err
				}
			}
			return msg
		})
	}
	events := make(chan tuiProcessStreamEvent, 16)
	return func() tea.Msg {
		if !group.begin() {
			return tuiProcessDoneMsg{action: action, name: name, err: context.Canceled}
		}
		output := &tuiProcessOutput{events: events}
		cmd.Stdout = output
		cmd.Stderr = output
		go func() {
			defer group.end()
			err := cmd.Run()
			select {
			case events <- tuiProcessStreamEvent{done: &tuiProcessDoneMsg{action: action, name: name, output: strings.TrimSpace(output.String()), err: err}}:
			case <-group.ctx.Done():
			}
			close(events)
		}()
		return receiveTUIProcessStream(events)
	}
}

func waitTUIProcessStream(stream <-chan tuiProcessStreamEvent) tea.Cmd {
	return func() tea.Msg { return receiveTUIProcessStream(stream) }
}

func receiveTUIProcessStream(stream <-chan tuiProcessStreamEvent) tea.Msg {
	event, ok := <-stream
	if !ok {
		done := tuiProcessDoneMsg{err: fmt.Errorf("process output stream closed unexpectedly")}
		event.done = &done
	}
	return tuiProcessStreamMsg{event: event, stream: stream}
}

// tuiProcessOutput retains a capped diagnostic tail while
// forwarding only bounded operation-progress lines to Bubble Tea. stdout and
// stderr may be copied concurrently by os/exec, hence the shared lock.
type tuiProcessOutput struct {
	mu           sync.Mutex
	output       bytes.Buffer
	pending      string
	lineOverflow bool
	events       chan<- tuiProcessStreamEvent
}

const tuiOutputLimit = 256 << 10
const tuiLineLimit = 16 << 10

func (w *tuiProcessOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	// Keep the tail, including when a single Write is larger than the budget.
	if len(p) >= tuiOutputLimit {
		w.output.Reset()
		_, _ = w.output.Write(p[len(p)-tuiOutputLimit:])
	} else {
		if excess := w.output.Len() + len(p) - tuiOutputLimit; excess > 0 {
			w.output.Next(excess)
		}
		_, _ = w.output.Write(p)
	}
	// Process input incrementally so a line without a newline never builds an
	// unbounded intermediate string. Oversized lines are excluded from progress.
	rest := p
	for len(rest) > 0 {
		end := bytes.IndexByte(rest, '\n')
		segment := rest
		if end >= 0 {
			segment = rest[:end]
		}
		if !w.lineOverflow {
			if len(w.pending)+len(segment) > tuiLineLimit {
				w.pending = ""
				w.lineOverflow = true
			} else {
				w.pending += string(segment)
			}
		}
		if end < 0 {
			break
		}
		if !w.lineOverflow {
			if line, ok := operationProgressLine(strings.TrimSuffix(w.pending, "\r")); ok {
				select {
				case w.events <- tuiProcessStreamEvent{progress: line}:
				default:
				}
			}
		}
		w.pending = ""
		w.lineOverflow = false
		rest = rest[end+1:]
	}
	w.mu.Unlock()
	return len(p), nil
}

func (w *tuiProcessOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.String()
}

func operationProgressLine(line string) (string, bool) {
	start := -1
	for _, marker := range []string{"downloading ", "creating persistent disk "} {
		if index := strings.Index(line, marker); index >= 0 && (start < 0 || index < start) {
			start = index
		}
	}
	if start < 0 {
		// Image pulls report one line per layer instead of a progress bar.
		// The CLI prefixes those with "gantry image: "; its failure line is
		// "gantry image <verb>: " (no space before the colon), so the two
		// never collide.
		if index := strings.Index(line, "gantry image: "); index >= 0 {
			progress := strings.TrimSpace(line[index+len("gantry image: "):])
			return progress, progress != ""
		}
		return "", false
	}
	line = line[start:]
	if !strings.Contains(line, "[") || !strings.Contains(line, "]") {
		return "", false
	}
	return line, true
}

func (m *sandboxTUIModel) beginStart(action string, request lifecycle.StartRequest) (tea.Model, tea.Cmd) {
	m.dialog = tuiNoDialog
	m.dialogScroll = 0
	m.busyAction, m.busyName, m.busyProgress = action, request.Name, ""
	m.selectNext = request.Name
	return m, tea.Batch(runTUIStartCmd(m.operations, m.service, action, request), m.ensureAnimation())
}

func runTUIStartCmd(group *dashboardOperations, service lifecycle.Service, action string, request lifecycle.StartRequest) tea.Cmd {
	return func() tea.Msg {
		if !group.begin() {
			return tuiProcessDoneMsg{action: action, name: request.Name, err: context.Canceled}
		}
		events := make(chan tuiProcessStreamEvent, 16)
		go func() {
			defer group.end()
			defer close(events)
			result, err := service.Start(group.ctx, request, func(event lifecycle.Progress) {
				select {
				case events <- tuiProcessStreamEvent{progress: event.Message}:
				default:
				}
			})
			done := &tuiProcessDoneMsg{action: action, name: request.Name, err: err}
			if err == nil {
				done.output = strings.Join(result.Warnings, "\n")
			}
			select {
			case events <- tuiProcessStreamEvent{done: done}:
			case <-group.ctx.Done():
			}
		}()
		return receiveTUIProcessStream(events)
	}
}

type dashboardOperations struct {
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	workers sync.WaitGroup
}

func newDashboardOperations() *dashboardOperations {
	ctx, cancel := context.WithCancel(context.Background())
	return &dashboardOperations{ctx: ctx, cancel: cancel}
}
func (group *dashboardOperations) begin() bool {
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.closed {
		return false
	}
	group.workers.Add(1)
	return true
}
func (group *dashboardOperations) end() { group.workers.Done() }
func (group *dashboardOperations) close() {
	group.mu.Lock()
	group.closed = true
	group.cancel()
	group.mu.Unlock()
	group.workers.Wait()
}
