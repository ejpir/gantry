package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/oauthbridge"
	"github.com/ejpir/gantry/internal/sandbox/oauthbridge/watchproto"
)

const oauthWatchReadyTimeout = 10 * time.Second

// startOAuthListenerWatch starts a trusted task in the guest network namespace
// and waits for its first procfs snapshot. This happens before daemon readiness,
// so an immediately launched OAuth CLI cannot beat listener discovery.
func (d *daemonRuntime) startOAuthListenerWatch() error {
	if d.broker == nil || d.broker.oauth == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	decoder := newOAuthWatchDecoder(d.broker.oauth, func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "daemon: oauth watcher: "+format+"\n", a...)
	})
	exited := make(chan error, 1)
	d.oauthWatchCancel = cancel
	d.oauthWatchWG.Add(1)
	go func() {
		defer d.oauthWatchWG.Done()
		status, err := d.broker.runOAuthWatchSession(ctx, decoder)
		decoder.Close()
		if err == nil && status != 0 {
			err = fmt.Errorf("guest helper exited %d", status)
		}
		if ctx.Err() == nil && err == nil {
			err = fmt.Errorf("guest helper exited unexpectedly")
		}
		if ctx.Err() == nil && err != nil {
			fmt.Fprintln(os.Stderr, "daemon: oauth watcher:", err)
		}
		exited <- err
	}()

	timer := time.NewTimer(oauthWatchReadyTimeout)
	defer timer.Stop()
	select {
	case <-decoder.Ready():
		fmt.Fprintln(os.Stderr, "daemon: oauth watcher ready (guest loopback listener discovery active)")
		return nil
	case err := <-exited:
		cancel()
		d.oauthWatchWG.Wait()
		if err == nil {
			err = fmt.Errorf("guest helper stopped before its first snapshot")
		}
		return fmt.Errorf("start OAuth listener watcher: %w", err)
	case <-timer.C:
		cancel()
		d.oauthWatchWG.Wait()
		return fmt.Errorf("start OAuth listener watcher: no snapshot within %s", oauthWatchReadyTimeout)
	}
}

func (d *daemonRuntime) stopOAuthListenerWatch() {
	if d.oauthWatchCancel != nil {
		d.oauthWatchCancel()
		d.oauthWatchCancel = nil
	}
	d.oauthWatchWG.Wait()
}

type oauthWatchDecoder struct {
	mu          sync.Mutex
	bridge      *oauthbridge.Bridge
	logf        func(string, ...any)
	buf         []byte
	ports       map[int]struct{}
	ready       chan struct{}
	readyOnce   sync.Once
	initialized bool
	closed      bool
	discardLine bool
}

func newOAuthWatchDecoder(bridge *oauthbridge.Bridge, logf func(string, ...any)) *oauthWatchDecoder {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &oauthWatchDecoder{
		bridge: bridge,
		logf:   logf,
		ports:  map[int]struct{}{},
		ready:  make(chan struct{}),
	}
}

func (d *oauthWatchDecoder) Ready() <-chan struct{} { return d.ready }

// Write consumes newline-delimited snapshots from the private guest-helper
// stream. It always drains input; malformed reports cannot wedge the task.
func (d *oauthWatchDecoder) Write(p []byte) (int, error) {
	written := len(p)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return len(p), nil
	}
	for len(p) > 0 {
		newline := bytes.IndexByte(p, '\n')
		chunk := p
		complete := false
		if newline >= 0 {
			chunk, p, complete = p[:newline], p[newline+1:], true
		} else {
			p = nil
		}
		if !d.discardLine {
			if len(d.buf)+len(chunk) > watchproto.MaxMessageBytes {
				d.buf = d.buf[:0]
				d.discardLine = true
				d.logf("discarded oversized snapshot")
			} else {
				d.buf = append(d.buf, chunk...)
			}
		}
		if !complete {
			break
		}
		if !d.discardLine {
			d.applyLine(d.buf)
		}
		d.buf = d.buf[:0]
		d.discardLine = false
	}
	return written, nil
}

func (d *oauthWatchDecoder) applyLine(line []byte) {
	var snapshot watchproto.Snapshot
	if err := json.Unmarshal(line, &snapshot); err != nil {
		d.logf("ignored malformed snapshot: %v", err)
		return
	}
	if len(snapshot.Ports) > watchproto.MaxPorts {
		d.logf("ignored snapshot with %d ports (limit %d)", len(snapshot.Ports), watchproto.MaxPorts)
		return
	}
	next := make(map[int]struct{}, len(snapshot.Ports))
	for _, port := range snapshot.Ports {
		if port > 0 && port <= 65535 {
			next[port] = struct{}{}
		}
	}
	if !d.initialized {
		// The daemon starts the watcher before publishing readiness. Treat
		// existing sockets as a baseline so long-running local services do not
		// consume OAuth gate slots; login listeners appear in later snapshots.
		d.initialized = true
		d.ports = next
		d.readyOnce.Do(func() { close(d.ready) })
		return
	}
	// Close first so a replacement flow can use a bounded listener slot in
	// the same snapshot transition.
	for port := range d.ports {
		if _, active := next[port]; !active {
			d.bridge.CloseGuestListener(port)
		}
	}
	// Preserve the guest's sorted order instead of ranging over a map.
	for _, port := range snapshot.Ports {
		if _, active := d.ports[port]; !active {
			d.bridge.OpenGuestListener(port)
		}
	}
	d.ports = next
}

func (d *oauthWatchDecoder) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	d.ports = map[int]struct{}{}
	d.mu.Unlock()
	d.bridge.CloseGuestListeners()
}
