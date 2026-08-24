package worker

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/workerproto"
)

const firstWorkerSlot = 3

// InheritedFile is one role-specific file capability installed at a fixed
// child descriptor/handle slot. Launch duplicates it into the child but never
// closes the caller's file; the role retains ownership until its boot
// acknowledgement commits the handoff.
type InheritedFile struct {
	Slot int
	File *os.File
}

// LaunchSpec describes only process-level worker mechanics. Bootstrap config,
// RPC operations, inherited-file validation, and failure policy remain owned
// by the VMM, network, and MCP worker packages.
type LaunchSpec struct {
	Role        workerproto.Role
	EntryPoint  string
	Environment []string
	Channels    []string
	// TransferableChannels names channels whose supervisor endpoint may be
	// handed to another child process. Windows creates these as inherited
	// Winsock connections instead of anonymous pipes; Unix channels are already
	// socketpairs. Entries must also appear in Channels.
	TransferableChannels []string
	InheritedFiles       []InheritedFile
	DiagnosticPath       string
	Confinement          string

	// ExitClosers are role-owned capabilities that must be revoked when the
	// process is reaped. Ownership transfers to Child only after a successful
	// spawn. Callers still own them when Launch returns an error.
	ExitClosers []io.Closer

	// ConfigureProcess rewrites argv and the already-allowlisted environment.
	// It exists for helper-process tests whose executable is a Go test binary;
	// production launch sites leave it nil.
	ConfigureProcess func(argv, environment *[]string)
}

// Child is the process-neutral supervisor handle returned by Launch. It owns
// process watching, bounded diagnostics, spawn-time containment, private
// channels, and the lifecycle state machine. A role decides whether an exit is
// fatal and which graceful-shutdown RPC to send.
type Child struct {
	Process     *os.Process
	Channels    map[string]net.Conn
	Diagnostics *boundedlog.Pipe
	Containment Containment
	Lifecycle   *Lifecycle

	role           workerproto.Role
	diagnosticPath string
	exitClosers    []io.Closer

	channelOnce sync.Once
	revokeOnce  sync.Once
	revokeErr   error

	bootstrapMu   sync.Mutex
	bootstrapSent bool
}

// Launch re-executes the current binary with an exact environment and
// capability table. The platform implementation creates private channels and
// applies namespace/Job confinement without exposing those details to roles.
func Launch(spec LaunchSpec) (*Child, error) {
	if err := validateLaunchSpec(spec); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	argv := []string{executable, spec.EntryPoint}
	// A non-nil empty slice is security-significant: os.StartProcess treats a
	// nil Env as a request to inherit the complete supervisor environment.
	environment := append([]string{}, spec.Environment...)
	if spec.ConfigureProcess != nil {
		spec.ConfigureProcess(&argv, &environment)
		if len(argv) == 0 {
			return nil, fmt.Errorf("%s worker process configuration removed argv", spec.Role)
		}
		if environment == nil {
			environment = []string{}
		}
	}
	if err := validateEnvironment(environment); err != nil {
		return nil, fmt.Errorf("%s worker environment: %w", spec.Role, err)
	}

	diagnostics, err := boundedlog.NewPipe(spec.DiagnosticPath)
	if err != nil {
		return nil, fmt.Errorf("open %s worker log broker: %w", roleLogName(spec.Role), err)
	}
	keepDiagnostics := false
	defer func() {
		if !keepDiagnostics {
			_ = diagnostics.Close()
		}
	}()

	process, channels, containment, err := launchPlatformProcess(
		executable, argv, environment, spec, diagnostics.Writer())
	// StartProcess has either duplicated the writer or failed. Releasing the
	// supervisor copy ensures worker death reaches the bounded drain as EOF.
	diagnostics.ReleaseWriter()
	if err != nil {
		return nil, err
	}

	child := &Child{
		Process:        process,
		Channels:       channels,
		Diagnostics:    diagnostics,
		Containment:    containment,
		Lifecycle:      NewLifecycle(),
		role:           spec.Role,
		diagnosticPath: spec.DiagnosticPath,
		exitClosers:    append([]io.Closer(nil), spec.ExitClosers...),
	}
	keepDiagnostics = true
	go child.watch()
	return child, nil
}

func validateLaunchSpec(spec LaunchSpec) error {
	if !spec.Role.Valid() {
		return fmt.Errorf("invalid worker role %q", spec.Role)
	}
	expectedEntry := "_" + string(spec.Role) + "-worker"
	if spec.EntryPoint != expectedEntry {
		return fmt.Errorf("worker role %q requires entry point %q, got %q", spec.Role, expectedEntry, spec.EntryPoint)
	}
	switch spec.Confinement {
	case "", "off", "auto", "required":
	default:
		return fmt.Errorf("worker %s has invalid confinement mode %q", spec.Role, spec.Confinement)
	}
	if len(spec.Channels) == 0 || spec.Channels[0] != "control" {
		return fmt.Errorf("worker %s channel 0 must be %q", spec.Role, "control")
	}
	seenNames := make(map[string]struct{}, len(spec.Channels))
	for index, name := range spec.Channels {
		if name == "" {
			return fmt.Errorf("worker %s channel %d has an empty name", spec.Role, index)
		}
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf("worker %s channel name %q is duplicated", spec.Role, name)
		}
		seenNames[name] = struct{}{}
	}
	seenTransferable := make(map[string]struct{}, len(spec.TransferableChannels))
	for _, name := range spec.TransferableChannels {
		if _, exists := seenNames[name]; !exists {
			return fmt.Errorf("worker %s transferable channel %q is not declared", spec.Role, name)
		}
		if _, exists := seenTransferable[name]; exists {
			return fmt.Errorf("worker %s transferable channel %q is duplicated", spec.Role, name)
		}
		seenTransferable[name] = struct{}{}
	}
	seenSlots := make(map[int]struct{}, len(spec.InheritedFiles))
	for index, inherited := range spec.InheritedFiles {
		if inherited.File == nil {
			return fmt.Errorf("worker %s inherited file %d is nil", spec.Role, index)
		}
		if inherited.Slot < firstWorkerSlot+len(spec.Channels) {
			return fmt.Errorf("worker %s inherited slot %d overlaps its channel table", spec.Role, inherited.Slot)
		}
		if _, exists := seenSlots[inherited.Slot]; exists {
			return fmt.Errorf("worker %s inherited slot %d is duplicated", spec.Role, inherited.Slot)
		}
		seenSlots[inherited.Slot] = struct{}{}
	}
	return validateEnvironment(spec.Environment)
}

func validateEnvironment(environment []string) error {
	seen := make(map[string]struct{}, len(environment))
	for index, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" || strings.IndexByte(entry, 0) >= 0 {
			return fmt.Errorf("entry %d is malformed", index)
		}
		if strings.HasPrefix(name, "GANTRY_WORKER_") {
			return fmt.Errorf("entry %q uses a reserved worker-bootstrap name", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("entry %q is duplicated", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func roleProcessName(role workerproto.Role) string { return string(role) + "-worker" }

func roleLogName(role workerproto.Role) string {
	if role == workerproto.RoleNet {
		return "network"
	}
	return strings.ToUpper(string(role))
}

func (c *Child) watch() {
	err := WaitProcess(c.Process, roleProcessName(c.role))
	err = errors.Join(err, c.revokeProcessCapabilities())
	if err != nil && c.diagnosticPath != "" {
		err = errors.Join(err, boundedlog.DiagnosticTail(roleProcessName(c.role), c.diagnosticPath))
	}
	// Publish process death before closing the supervisor channel ends. Role
	// relay goroutines can therefore distinguish teardown from an independent
	// protocol failure.
	c.Lifecycle.Exit(err)
	c.CloseChannels()
}

func (c *Child) revokeProcessCapabilities() error {
	c.revokeOnce.Do(func() {
		if c.Containment != nil {
			c.revokeErr = errors.Join(c.revokeErr, c.Containment.Close())
			c.Containment = nil
		}
		if c.Diagnostics != nil {
			c.revokeErr = errors.Join(c.revokeErr, c.Diagnostics.Close())
		}
		for _, closer := range c.exitClosers {
			if closer != nil {
				c.revokeErr = errors.Join(c.revokeErr, closer.Close())
			}
		}
		c.exitClosers = nil
	})
	return c.revokeErr
}

// CloseChannels revokes every private supervisor-to-worker transport. It is
// safe to call during graceful role shutdown and again from the process
// watcher.
func (c *Child) CloseChannels() {
	if c == nil {
		return
	}
	c.channelOnce.Do(func() {
		for _, channel := range c.Channels {
			if channel != nil {
				_ = channel.Close()
			}
		}
	})
}

// Done closes once the worker has been reaped and its containment,
// diagnostics, and exit closers have been revoked. Channel closure follows
// lifecycle publication so role relays can classify teardown correctly.
func (c *Child) Done() <-chan struct{} { return c.Lifecycle.Done() }

// Err is stable after Done closes.
func (c *Child) Err() error { return c.Lifecycle.Err() }

// BeginStop marks an intentional role-directed shutdown.
func (c *Child) BeginStop() { c.Lifecycle.BeginStop() }

// WaitExit waits for graceful process exit and escalates to Kill after grace.
func (c *Child) WaitExit(grace time.Duration) error {
	if c == nil || c.Process == nil {
		return fmt.Errorf("worker process unavailable")
	}
	return c.Lifecycle.WaitExit(grace, c.Process.Kill)
}

// Terminate closes every channel, kills the worker, and waits a bounded time
// for the process watcher to reap it. Bootstrap failure paths use this before
// returning role-owned assets to a monolithic fallback.
func (c *Child) Terminate(grace time.Duration) error {
	if c == nil {
		return nil
	}
	c.BeginStop()
	c.CloseChannels()
	if c.Process != nil {
		_ = c.Process.Kill()
	}
	return c.WaitExit(grace)
}

// Bootstrap is a nonce generated for one control handshake. Independent data
// channels must receive the same nonce before a worker accepts their traffic.
type Bootstrap struct {
	child *Child
	nonce []byte
	bound map[string]struct{}
}

// BeginBootstrap sends the typed role handshake over the control channel.
// Roles may transfer setup descriptors before calling BindChannels.
func (c *Child) BeginBootstrap(config any) (*Bootstrap, error) {
	if c == nil {
		return nil, fmt.Errorf("worker child unavailable")
	}
	c.bootstrapMu.Lock()
	if c.bootstrapSent {
		c.bootstrapMu.Unlock()
		return nil, fmt.Errorf("%s bootstrap already sent", roleProcessName(c.role))
	}
	// Any failure after this point leaves the byte stream ambiguous. The caller
	// must terminate the child rather than replaying a second handshake.
	c.bootstrapSent = true
	c.bootstrapMu.Unlock()
	control := c.Channels["control"]
	if control == nil {
		return nil, fmt.Errorf("%s control channel unavailable", roleProcessName(c.role))
	}
	nonce, err := workerproto.NewNonce()
	if err != nil {
		return nil, err
	}
	if err := workerproto.SendHandshake(control, c.role, nonce, config); err != nil {
		return nil, err
	}
	return &Bootstrap{child: c, nonce: nonce, bound: make(map[string]struct{})}, nil
}

// BindChannels authenticates the named non-control channels for this launch.
func (b *Bootstrap) BindChannels(names ...string) error {
	if b == nil || b.child == nil {
		return fmt.Errorf("worker bootstrap unavailable")
	}
	for _, name := range names {
		if name == "control" {
			return fmt.Errorf("worker bootstrap cannot nonce-bind the control channel")
		}
		if _, exists := b.bound[name]; exists {
			return fmt.Errorf("worker channel %q is already nonce-bound", name)
		}
		channel := b.child.Channels[name]
		if channel == nil {
			return fmt.Errorf("worker channel %q unavailable", name)
		}
		if err := workerproto.WriteNonce(channel, b.nonce); err != nil {
			return fmt.Errorf("bind worker channel %q: %w", name, err)
		}
		b.bound[name] = struct{}{}
	}
	return nil
}

// Bootstrap sends a handshake and immediately nonce-binds its data channels.
func (c *Child) Bootstrap(config any, channelNames ...string) error {
	bootstrap, err := c.BeginBootstrap(config)
	if err != nil {
		return err
	}
	return bootstrap.BindChannels(channelNames...)
}
