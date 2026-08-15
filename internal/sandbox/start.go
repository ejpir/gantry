package sandbox

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/secret"
)

func CmdStart(argv []string) int {
	timeline := newLauncherBootTimeline()
	timeline.mark("launcher started")

	fs := flag.NewFlagSet("start", flag.ExitOnError)
	rf := RegisterRunFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: gantry start <name> [flags]   (name: letters, digits, ._-)

Create a long-lived sandbox VM running an OCI image; attach with
'gantry exec <name>' (docker-exec semantics, concurrent sessions OK).

examples:
  gantry start dev -image alpine:latest
  gantry start dev -image debian:bookworm-slim -cpus 2 -mem 1024
  gantry start dev -image ghcr.io/org/app@sha256:... -share code=$HOME/repos,ro
  gantry start agent -secret GITHUB_TOKEN -image python:3.12 -net-policy allow-github.json
  gantry start dev -runtime runsc -image alpine:latest
  gantry start dev -image ./my-rootfs.erofs

flags:`)
		fs.PrintDefaults()
	}
	if len(argv) > 0 && (argv[0] == "-h" || argv[0] == "--help") {
		fs.Usage()
		return 0
	}
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") || !validSandboxName(argv[0]) {
		fs.Usage()
		return 2
	}
	name, fargv := argv[0], argv[1:]

	rf.Name = name
	_ = fs.Parse(fargv)
	progress := gutil.NewProgressPrinter(os.Stdout, "gantry start: ")
	cfg, warnings, err := rf.resolve(fs, progress.Printf, timeline.mark)
	progress.Finish()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "gantry start:", w)
	}
	secrets, _, err := rf.ResolveSecrets()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry start:", err)
		return 1
	}
	timeline.mark("launcher secrets resolved")
	if len(secrets) > 0 && cfg.Net && cfg.NetPol == "" {
		fmt.Fprintf(os.Stderr, `gantry start: %d secret(s) injected with the default egress policy (internet
allowed). Consider -net-policy with a domain allowlist so an injected
agent cannot send them anywhere.
`, len(secrets))
	}

	return launchSandboxModeWithSpawnerTiming(name, cfg, secrets, true, false, startSandboxDaemon, timeline.mark)
}

// launcherBootTimeline covers the part of startup which precedes the daemon's
// own clock: flag resolution, registry freshness, writable-layer setup,
// durable configuration, and process launch. It is intentionally enabled by
// the same low-overhead GANTRY_BOOT_TIMING switch as daemon milestones.
type launcherBootTimeline struct {
	started time.Time
	enabled bool
}

func newLauncherBootTimeline() *launcherBootTimeline {
	return &launcherBootTimeline{
		started: time.Now(),
		enabled: os.Getenv("GANTRY_BOOT_TIMING") != "",
	}
}

func (t *launcherBootTimeline) mark(phase string) {
	if t == nil || !t.enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "boot-timing: %-36s %9.3f ms\n", phase, float64(time.Since(t.started))/float64(time.Millisecond))
}

// CmdResume boots a stopped sandbox from its persisted configuration. The
// dashboard's Start action invokes the same CLI primitive asynchronously,
// avoiding duplicate daemon lifecycle code. Secret values are never persisted;
// configured names must be present in Gantry's current environment.
func CmdResume(name string) int {
	launchLock, err := holdSandboxLaunchLock(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry resume:", err)
		return 1
	}
	defer func() { _ = launchLock.Close() }()

	dir := sandboxDir(name)
	b, err := os.ReadFile(filepath.Join(dir, "sandbox.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "gantry resume: sandbox %q has no saved configuration: %v\n", name, err)
		return 1
	}
	var cfg RunConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "gantry resume: sandbox %q has a corrupt configuration: %v\n", name, err)
		return 1
	}
	secrets := make(map[string]secret.Value, len(cfg.SecretNames))
	for _, secretName := range cfg.SecretNames {
		name, value, err := secret.Parse(secretName, os.LookupEnv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gantry resume:", err)
			return 1
		}
		secrets[name] = value
	}
	return launchSandboxLocked(name, cfg, secrets, false, false, startSandboxDaemon)
}

const daemonReadySocketName = "start-ready.sock"

type daemonReadyListener struct {
	listener net.Listener
	path     string
	result   <-chan error
}

// newDaemonReadyListener creates a one-shot, event-driven readiness channel.
// The ready file remains the durable state marker and polling fallback, but
// the normal start path no longer waits for its next 100 ms poll interval.
func newDaemonReadyListener(dir string) (*daemonReadyListener, error) {
	path := filepath.Join(dir, daemonReadySocketName)
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := secureLocalEndpoint(path); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer func() { _ = conn.Close() }()
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			var signal [1]byte
			_, err = io.ReadFull(conn, signal[:])
			if err == nil && signal[0] != 1 {
				err = fmt.Errorf("invalid daemon readiness signal %d", signal[0])
			}
		}
		result <- err
	}()
	return &daemonReadyListener{listener: listener, path: path, result: result}, nil
}

func (r *daemonReadyListener) Close() {
	if r == nil {
		return
	}
	_ = r.listener.Close()
	_ = os.Remove(r.path)
}

func notifyDaemonReady(path string) error {
	if path == "" {
		return nil
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte{1})
	return err
}

func launchSandbox(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig bool) int {
	return launchSandboxMode(name, cfg, secrets, replaceConfig, false)
}

func launchSandboxMode(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig, transient bool) int {
	return launchSandboxModeWithSpawner(name, cfg, secrets, replaceConfig, transient, startSandboxDaemon)
}

func launchSandboxModeWithSpawner(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig, transient bool, spawn sandboxDaemonSpawner) int {
	return launchSandboxModeWithSpawnerTiming(name, cfg, secrets, replaceConfig, transient, spawn, nil)
}

func launchSandboxModeWithSpawnerTiming(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig, transient bool, spawn sandboxDaemonSpawner, milestone func(string)) int {
	return launchSandboxModeWithSpawnerTimingIO(name, cfg, secrets, replaceConfig, transient, spawn, milestone, os.Stdout, os.Stderr)
}

func launchSandboxModeWithSpawnerTimingIO(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig, transient bool, spawn sandboxDaemonSpawner, milestone func(string), output, errorOutput io.Writer) int {
	launchLock, err := holdSandboxLaunchLock(name)
	if err != nil {
		_, _ = fmt.Fprintln(errorOutput, sandboxLaunchLabel(transient)+":", err)
		return 1
	}
	if milestone != nil {
		milestone("launcher launch lock acquired")
	}
	defer func() { _ = launchLock.Close() }()
	return launchSandboxLockedTimingIO(name, cfg, secrets, replaceConfig, transient, spawn, milestone, output, errorOutput)
}

type sandboxDaemonProcess interface {
	PID() int
	SendHandshake(string) error
	Wait() error
	Kill() error
}

type execSandboxDaemon struct {
	cmd       *exec.Cmd
	handshake *os.File
}

func (p *execSandboxDaemon) PID() int { return p.cmd.Process.Pid }

func (p *execSandboxDaemon) SendHandshake(payload string) error {
	if p.handshake == nil {
		return fmt.Errorf("daemon handshake is already closed")
	}
	written, writeErr := io.WriteString(p.handshake, payload)
	if writeErr == nil && written != len(payload) {
		writeErr = io.ErrShortWrite
	}
	closeErr := p.handshake.Close()
	p.handshake = nil
	return errors.Join(writeErr, closeErr)
}

func (p *execSandboxDaemon) Wait() error { return p.cmd.Wait() }

func (p *execSandboxDaemon) Kill() error {
	var closeErr error
	if p.handshake != nil {
		closeErr = p.handshake.Close()
		p.handshake = nil
	}
	return errors.Join(closeErr, p.cmd.Process.Kill())
}

type sandboxDaemonSpawner func(*exec.Cmd) (sandboxDaemonProcess, error)

var makeConfigDurable = atomicfile.MakeDurable

func startSandboxDaemon(cmd *exec.Cmd) (sandboxDaemonProcess, error) {
	readHandshake, writeHandshake, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create daemon handshake gate: %w", err)
	}
	cmd.Stdin = readHandshake
	if err := cmd.Start(); err != nil {
		_ = readHandshake.Close()
		_ = writeHandshake.Close()
		return nil, err
	}
	// Start duplicated the read end into the child. The parent retains only
	// the write gate: if it crashes before publishing vmm.pid, EOF makes the
	// child fail its mandatory handshake instead of becoming an untracked VM.
	_ = readHandshake.Close()
	return &execSandboxDaemon{cmd: cmd, handshake: writeHandshake}, nil
}

func sandboxLaunchLabel(transient bool) string {
	label := "gantry start"
	if transient {
		label = "gantry exec"
	}
	return label
}

func launchSandboxLocked(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig, transient bool, spawn sandboxDaemonSpawner) int {
	return launchSandboxLockedTiming(name, cfg, secrets, replaceConfig, transient, spawn, nil)
}

func launchSandboxLockedTiming(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig, transient bool, spawn sandboxDaemonSpawner, milestone func(string)) int {
	return launchSandboxLockedTimingIO(name, cfg, secrets, replaceConfig, transient, spawn, milestone, os.Stdout, os.Stderr)
}

func launchSandboxLockedTimingIO(name string, cfg RunConfig, secrets map[string]secret.Value, replaceConfig, transient bool, spawn sandboxDaemonSpawner, milestone func(string), output, errorOutput io.Writer) int {
	// Human diagnostics are best effort: write failures must not replace the
	// lifecycle status, and buffers used by the manager cannot fail.
	writeLine := func(writer io.Writer, args ...any) { _, _ = fmt.Fprintln(writer, args...) }
	writef := func(writer io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(writer, format, args...) }
	mark := func(phase string) {
		if milestone != nil {
			milestone(phase)
		}
	}
	label := sandboxLaunchLabel(transient)
	dir := sandboxDir(name)
	// The pid file is diagnostic; the daemon's held lifetime lock is the
	// authoritative proof. Checking both while holding the stable launch lock
	// closes the window around pid creation and stale/corrupt pid files.
	if _, alive := sandboxPID(name); alive || sandboxLockHeld(dir) {
		writef(errorOutput, "%s: sandbox %q is already running\n", label, name)
		return 1
	}
	handshake, err := secretsHandshakeJSON(secrets)
	if err != nil {
		writeLine(errorOutput, label+":", err)
		return 1
	}

	if replaceConfig {
		if err := os.RemoveAll(dir); err != nil {
			writeLine(errorOutput, label+":", err)
			return 1
		}
	}
	// The broker has no application-layer authentication: the platform's
	// private directory permissions are the access boundary between a local
	// user and a root shell inside the sandbox (plus its rw host shares).
	if err := createSandboxDirectory(dir); err != nil {
		writeLine(errorOutput, label+":", err)
		return 1
	}
	cleanupSandboxRuntime(dir)
	mark("launcher state directory prepared")
	var configDurable <-chan error
	if replaceConfig {
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			writeLine(errorOutput, label+":", err)
			return 1
		}
		configPath := filepath.Join(dir, "sandbox.json")
		// Publish atomically before spawn so the daemon consumes exactly this
		// configuration. Where supported, overlap the file+directory durability
		// barrier with guest boot, but do not commit the launch until it succeeds.
		// Windows retains its write-through rename because reopening and syncing a
		// published file is not equivalent there. Transient state needs no barrier.
		writeConfig := atomicfile.WriteFile
		deferDurability := !transient && atomicfile.CanMakeDurableAfterCommit()
		if !transient && !deferDurability {
			writeConfig = atomicfile.WriteFileDurable
		}
		if err := writeConfig(configPath, append(b, '\n'), 0o600); err != nil {
			writeLine(errorOutput, label+":", err)
			return 1
		}
		mark("launcher configuration published")
		if deferDurability {
			result := make(chan error, 1)
			configDurable = result
			go func() { result <- makeConfigDurable(configPath) }()
		} else if !transient {
			mark("launcher configuration persisted")
		}
	} else if !transient {
		writef(output, "gantry start: using saved configuration for %q\n", name)
	}

	// Detached daemon: same binary, signed (this is why start goes through
	// scripts/run-macos.sh on macOS: build+codesign first).
	exe, err := os.Executable()
	if err != nil {
		writeLine(errorOutput, label+":", err)
		return 1
	}
	daemonLogPath := filepath.Join(dir, "daemon.log")
	if err := rotatePreviousLog(daemonLogPath); err != nil {
		writeLine(errorOutput, label+": preserve previous daemon log:", err)
		return 1
	}
	logf, err := os.Create(daemonLogPath)
	if err != nil {
		writeLine(errorOutput, label+":", err)
		return 1
	}
	defer func() { _ = logf.Close() }()

	// Prefer a one-shot readiness socket over polling. AF_UNIX is available on
	// the primary platforms; if a host cannot create it, the ready-file ticker
	// below remains a fully functional fallback.
	readyListener, _ := newDaemonReadyListener(dir)
	if readyListener != nil {
		defer readyListener.Close()
	}
	daemonArgs := []string{"daemon", name}
	var readySignal <-chan error
	if readyListener != nil {
		daemonArgs = append(daemonArgs, readyListener.path)
		readySignal = readyListener.result
	}
	cmd := exec.Command(exe, daemonArgs...)
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = logf, logf
	// The daemon receives secrets via the stdin handshake; it must not
	// ALSO inherit them through the environment — /proc/<pid>/environ is
	// host state readable by the same uid, so an inherited copy would
	// break docs/secrets.md rule 1 (values live in memory only). Scrub
	// exactly the injected keys; everything else (HOME, PATH, proxy vars
	// for image pulls, GANTRY_* knobs) passes through unchanged.
	cmd.Env = scrubbedEnv(os.Environ(), secrets)
	detachDaemon(cmd)
	if spawn == nil {
		writeLine(errorOutput, label+": spawn daemon: unavailable")
		return 1
	}
	process, err := spawn(cmd)
	if err != nil {
		writeLine(errorOutput, label+": spawn daemon:", err)
		return 1
	}
	mark("launcher daemon spawned")
	pid := process.PID()
	if pid <= 0 {
		_ = process.Kill()
		_ = process.Wait()
		writeLine(errorOutput, label+": spawn daemon: invalid process id")
		return 1
	}
	if err := os.WriteFile(filepath.Join(dir, "vmm.pid"), []byte(fmt.Sprint(pid)), 0o600); err != nil {
		_ = process.Kill()
		waitErr := process.Wait()
		writef(errorOutput, "%s: record daemon pid: %v (wait: %v)\n", label, err, waitErr)
		return 1
	}
	if err := process.SendHandshake(handshake); err != nil {
		_ = process.Kill()
		waitErr := process.Wait()
		writef(errorOutput, "%s: deliver daemon handshake: %v (wait: %v)\n", label, err, waitErr)
		return 1
	}
	mark("launcher handshake delivered")
	exited := make(chan error, 1)
	go func() { exited <- process.Wait() }()
	abortUncommittedDaemon := func() error {
		killErr := process.Kill()
		select {
		case waitErr := <-exited:
			return errors.Join(killErr, waitErr)
		case <-time.After(5 * time.Second):
			return errors.Join(killErr, fmt.Errorf("timed out reaping daemon"))
		}
	}

	if transient {
		writef(output, "gantry exec: VM booting (vmm pid %d)\n", pid)
	} else {
		writef(output, "gantry start: sandbox %q booting (vmm pid %d)\n", name, pid)
	}
	readyPath := filepath.Join(dir, "ready")
	announceReady := func() int {
		mark("launcher readiness received")
		if configDurable != nil {
			if err := <-configDurable; err != nil {
				waitErr := abortUncommittedDaemon()
				writef(errorOutput, "%s: persist configuration: %v (wait: %v)\n", label, err, waitErr)
				return 1
			}
			configDurable = nil
			mark("launcher configuration persisted")
		}
		// Readiness commits the launch-lock handoff only after the child holds
		// the in-directory lifetime lock. This makes a missing/corrupt pid file
		// harmless and prevents a forged/stale ready marker from releasing the
		// stable serialization boundary around an unowned daemon.
		if !sandboxLockHeld(dir) {
			waitErr := abortUncommittedDaemon()
			writef(errorOutput, "%s: daemon reported readiness without acquiring its lifetime lock (wait: %v)\n", label, waitErr)
			return 1
		}
		mark("launcher launch committed")
		if transient {
			writeLine(output, "gantry exec: VM ready")
		} else {
			writef(output, "gantry start: sandbox %q is up — attach with: gantry exec %s\n", name, name)
		}
		return 0
	}
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	fallbackPoll := time.NewTicker(100 * time.Millisecond)
	defer fallbackPoll.Stop()
	for {
		select {
		case err := <-readySignal:
			if err == nil {
				return announceReady()
			}
			// A failed or malformed event does not make boot fail: the ready
			// file remains the compatibility fallback.
			readySignal = nil
		case <-fallbackPoll.C:
			if gutil.FileExists(readyPath) {
				return announceReady()
			}
		case err := <-exited:
			writef(errorOutput, "%s: daemon exited during boot: %v\n", label, err)
			dumpTailTo(errorOutput, filepath.Join(dir, "console.log"))
			dumpTailTo(errorOutput, filepath.Join(dir, "daemon.log"))
			return 1
		case <-timeout.C:
			if !sandboxLockHeld(dir) {
				waitErr := abortUncommittedDaemon()
				writef(errorOutput, "%s: daemon did not acquire its lifetime lock before startup timed out (wait: %v)\n", label, waitErr)
			}
			writef(errorOutput, "%s: timed out waiting for the guest RPC connection; see %s\n", label, dir)
			dumpTailTo(errorOutput, filepath.Join(dir, "console.log"))
			dumpTailTo(errorOutput, filepath.Join(dir, "daemon.log"))
			return 1
		}
	}
}
