package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
	"github.com/ejpir/gantry/internal/sandbox/credhelper"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/sandbox/rwlayer"
)

var errSandboxNotRunning = errors.New("sandbox is not running")

func CmdLs() int {
	ents, err := os.ReadDir(layout.Root())
	if err != nil {
		fmt.Println("no sandboxes (create one with: gantry start <name>)")
		return 0
	}
	sandboxes := ents[:0]
	for _, entry := range ents {
		if entry.IsDir() && layout.ValidName(entry.Name()) {
			sandboxes = append(sandboxes, entry)
		}
	}
	if len(sandboxes) == 0 {
		fmt.Println("no sandboxes (create one with: gantry start <name>)")
		return 0
	}
	fmt.Printf("%-20s %-10s %-8s %-24s %s\n", "NAME", "STATE", "PID", "SECRETS", "IMAGE")
	for _, e := range sandboxes {
		name := e.Name()
		state, pidStr := "stopped", "-"
		if pid, alive := layout.PID(name); alive {
			state, pidStr = "running", fmt.Sprint(pid)
		}
		image, secrets := "-", "-"
		if b, err := os.ReadFile(filepath.Join(layout.Dir(name), "sandbox.json")); err == nil {
			var cfg config.RunConfig
			if json.Unmarshal(b, &cfg) == nil {
				image = filepath.Base(cfg.Image)
				if cfg.RW {
					image += " (rw)"
				}
				if len(cfg.SecretNames) > 0 {
					secrets = strings.Join(cfg.SecretNames, ",")
				}
			}
		}
		fmt.Printf("%-20s %-10s %-8s %-24s %s\n", name, state, pidStr, secrets, image)
	}
	return 0
}

func CmdStop(name string) int {
	if err := stopSandbox(name); err != nil {
		if errors.Is(err, errSandboxNotRunning) {
			fmt.Fprintf(os.Stderr, "gantry stop: sandbox %q is not running\n", name)
		} else {
			fmt.Fprintln(os.Stderr, "gantry stop:", err)
		}
		return 1
	}
	fmt.Printf("gantry stop: sandbox %q stopped\n", name)
	return 0
}

func stopSandbox(name string) error {
	pid, alive := layout.PID(name)
	if !alive {
		return errSandboxNotRunning
	}
	// ctl.sock is authenticated by the same-UID check on Unix and by the
	// verified protected DACL on Windows. Prefer the daemon's own shutdown
	// state transition so guest sync and device flush run on every platform.
	if err := requestDaemonShutdown(name); err != nil && layout.ProcAlive(pid) {
		if signalErr := layout.Terminate(pid); signalErr != nil && layout.ProcAlive(pid) {
			return fmt.Errorf("terminate sandbox %q (control request: %v): %w", name, err, signalErr)
		}
	}
	// Grace window: the daemon's shutdown path syncs the guest and
	// flushes devices (bounded internally at ~5s) — give it room before
	// escalating to a power cut (review finding 5).
	for i := 0; i < 120; i++ {
		if !layout.ProcAlive(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if layout.ProcAlive(pid) {
		_ = layout.Kill(pid)
	}
	// kill the sandbox's gvproxy too (defers don't run if the daemon was
	// SIGKILLed, orphaning it)
	dir := layout.Dir(name)
	if b, err := os.ReadFile(filepath.Join(dir, "gvproxy.pid")); err == nil {
		var gpid int
		if _, _ = fmt.Sscanf(string(b), "%d", &gpid); gpid > 0 {
			_ = layout.Kill(gpid)
		}
	}
	// Clean runtime files; sandbox.json stays so CmdResume and the dashboard
	// can boot the same VM configuration again.
	cleanupSandboxRuntime(dir)
	return nil
}

type daemonShutdownResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func requestDaemonShutdown(name string) error {
	response, err := controlproto.Call[daemonShutdownResponse](name, controlproto.Request{
		Op: "daemon.shutdown",
		ID: controlproto.NewRequestID("shutdown"),
	})
	if err != nil {
		return err
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "request refused"
		}
		return errors.New(response.Error)
	}
	return nil
}

func cleanupSandboxRuntime(dir string) {
	for _, f := range []string{"vmm.pid", "gvproxy.pid", "ready", daemonReadySocketName, "ctl.sock", "1025.sock", "listen-1026.sock", credhelper.SockName, "net.sock", "net.sock.client", "gvproxy-api.sock", "shares.json"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
}

func CmdDelete(name string) int {
	if err := deleteSandbox(name); err != nil {
		fmt.Fprintln(os.Stderr, "gantry delete:", err)
		return 1
	}
	fmt.Printf("gantry delete: sandbox %q deleted\n", name)
	return 0
}

func deleteSandbox(name string) error {
	if _, alive := layout.PID(name); alive {
		if err := stopSandbox(name); err != nil && !errors.Is(err, errSandboxNotRunning) {
			return err
		}
	}
	if err := os.RemoveAll(layout.Dir(name)); err != nil {
		return err
	}
	rwlayer.Forget(name)
	return nil
}
