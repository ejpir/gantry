package manager

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/policy"
	"github.com/ejpir/gantry/internal/sandbox/lifecycle"
)

// Lifecycle is the sandbox lifecycle this API drives. The sandbox package
// implements it; the manager speaks HTTP and never learns how a VM is
// started, stopped or entered.
type Lifecycle interface {
	lifecycle.Service

	// Stop reports ErrNotRunning when the sandbox is already stopped.
	Stop(name string) error

	// Delete removes a sandbox and is idempotent.
	Delete(name string) error

	// Exec runs one command inside a running sandbox and captures its output,
	// reporting ErrExecTimeout or ErrExecOutputLimit when those bounds are hit.
	Exec(ctx context.Context, name string, request ExecRequest) (ExecResult, error)
}

// OrganizationPolicyService is the optional live-policy capability supplied
// by the local sandbox lifecycle. Keeping it separate preserves manager
// backends which intentionally support only controlled restarts.
type OrganizationPolicyService interface {
	ApplyOrganizationPolicy(context.Context, string, *policy.Config) error
}

// ImageService is the image-cache capability of a manager backend. Keeping it
// separate lets embedded/local lifecycle users omit registry support.
type ImageService interface {
	// ListImages returns the manager host's image cache.
	ListImages() ([]managerapi.Image, error)

	// PullImage resolves and builds an image reference into the host cache.
	// It blocks for the whole pull (the transport runs it asynchronously);
	// platform is the target architecture ("" = host arch) and progress
	// receives human-readable log lines as the pull advances.
	PullImage(ctx context.Context, ref, platform string, progress func(string)) (managerapi.Image, error)

	// DeleteImage removes a cached image by ref or digest, reporting
	// ErrImageNotFound for unknown ones, and returns what was removed.
	DeleteImage(ref string) (managerapi.Image, error)
}

// RunVMService runs the existing low-level VM launcher in an isolated helper.
// It must honor cancellation, bound retained output and terminate the VM before
// returning. The command's process exit is data, not a lifecycle error.
type RunVMService interface {
	RunVM(context.Context, managerapi.RunVMRequest) (managerapi.ExecResult, error)
}

// SSHService exposes only the install public key and a validated SSH socket.
// It cannot dial arbitrary sockets or addresses supplied by the caller.
type SSHService interface {
	SSHHostKey() (managerapi.SSHHostKey, error)
	DialSSH(ctx context.Context, name string) (net.Conn, error)
}

// ExecRequest is one captured command run.
type ExecRequest struct {
	Args           []string
	Cwd            string
	Stdin          string
	Timeout        time.Duration
	MaxOutputBytes int64
}

// ExecResult is what the guest process produced.
type ExecResult struct {
	ExitCode  int
	Output    []byte
	Truncated bool
}

// The lifecycle conditions this API turns into distinct HTTP statuses. The
// implementation reports them; the transport maps them to 409, 408, 413 and
// 404.
var (
	ErrNotRunning      = errors.New("sandbox is not running")
	ErrExecTimeout     = errors.New("exec timed out")
	ErrExecOutputLimit = errors.New("exec output limit exceeded")
	ErrImageNotFound   = errors.New("image not found")
)

// tryAcquireSlot / releaseSlot are non-blocking semaphore operations: a full
// limit rejects new work immediately rather than queueing goroutines behind
// it. The daemon's broker keeps its own copy for the same reason.
func tryAcquireSlot(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseSlot(slots chan struct{}) { <-slots }

// NewHandler builds the manager's HTTP handler over lifecycle. Cmd serves it
// on a same-user unix socket; exposing it separately lets callers mount the
// API themselves and lets tests drive it without a listener.
func NewHandler(lifecycle Lifecycle) http.Handler { return newManagerService(lifecycle).handler() }
