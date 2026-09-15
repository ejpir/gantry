package remote

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
)

// Events consumes one SSE connection. Readiness is reported only after the
// stream is subscribed: callers then resnapshot without a lost-event window.
// The server has bounded live events, not durable history; reconnects must
// resnapshot instead of pretending Last-Event-ID provides guaranteed replay.
func (c *Client) Events(ctx context.Context, ready func() error, event func(managerapi.Event) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(45*time.Second, cancel)
	defer idle.Stop()
	request, err := c.newRequest(ctx, http.MethodGet, "/v1/events", nil, false)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := c.http.Do(request)
	if err != nil {
		return unwrapTLS(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return &Error{Status: response.StatusCode, Message: response.Status}
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		return errors.New("manager did not return an SSE stream")
	}
	if ready != nil {
		if err := ready(); err != nil {
			return err
		}
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var data strings.Builder
	for scanner.Scan() {
		idle.Reset(45 * time.Second)
		line := scanner.Text()
		if line == "" {
			if data.Len() > 0 {
				var value managerapi.Event
				if err := json.Unmarshal([]byte(data.String()), &value); err != nil {
					return fmt.Errorf("invalid SSE event: %w", err)
				}
				if event != nil {
					if err := event(value); err != nil {
						return err
					}
				}
				data.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			if data.Len()+len(line) > 64<<10 {
				return errors.New("SSE event exceeds 64 KiB")
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			data.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return io.EOF
}

// WatchSnapshot is read-only remote inventory; unavailable sources have no
// rows, preventing stale state from being mistaken for current state.
type WatchSnapshot struct {
	Remote    string
	Sandboxes []managerapi.Sandbox
	Error     string
}

// WatchSandboxes reconnects with bounded backoff and resnapshots after every
// subscription. Periodic resync also catches changes made by host-local CLI
// processes (which need not emit manager events).
func (c *Client) WatchSandboxes(ctx context.Context, update func(WatchSnapshot)) {
	backoff := time.Second
	for ctx.Err() == nil {
		streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resnapshot := func() error {
			probe, done := context.WithTimeout(streamCtx, 10*time.Second)
			defer done()
			rows, err := c.ListSandboxes(probe)
			if err == nil {
				update(WatchSnapshot{Remote: c.profile.Name, Sandboxes: rows})
				backoff = time.Second
			}
			return err
		}
		err := c.Events(streamCtx, resnapshot, func(managerapi.Event) error { return resnapshot() })
		periodic := errors.Is(streamCtx.Err(), context.DeadlineExceeded)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if periodic {
			continue
		}
		update(WatchSnapshot{Remote: c.profile.Name, Error: fmt.Sprintf("unavailable: %v; retrying", err)})
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 10*time.Second)
	}
}

func remoteEvents(ctx context.Context, out, errs io.Writer, target string, client *Client, argv []string) int {
	if len(argv) != 0 {
		_, _ = fmt.Fprintln(errs, "usage: gantry events -remote NAME")
		return 2
	}
	for ctx.Err() == nil {
		err := client.Events(ctx, nil, func(event managerapi.Event) error { return json.NewEncoder(out).Encode(event) })
		if ctx.Err() != nil {
			break
		}
		_, _ = fmt.Fprintf(errs, "remote %q event stream disconnected: %v; reconnecting (live events, no replay)\n", target, err)
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	return 0
}
