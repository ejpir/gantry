package manager

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/secret"
)

// Lifecycle is the sandbox lifecycle this API drives. The sandbox package
// implements it; the manager speaks HTTP and never learns how a VM is
// started, stopped or entered.
type Lifecycle interface {
	// Resolve turns registered run flags into a boot configuration using only
	// locally cached assets — an API request must never block on a network
	// fetch — and returns any warnings alongside it.
	Resolve(flags *config.RunFlags, fs *flag.FlagSet) (config.RunConfig, []string, error)

	// Launch boots name and returns a CLI-style exit status, writing progress
	// to stdout and diagnostics to stderr. replaceConfig rewrites cfg for a
	// create; a start re-reads saved config and env secrets under the stable
	// cross-process launch lock rather than trusting the HTTP preflight copy.
	Launch(name string, cfg config.RunConfig, secrets map[string]secret.Value, replaceConfig bool, stdout, stderr io.Writer) int

	// Stop reports ErrNotRunning when the sandbox is already stopped.
	Stop(name string) error

	// Delete removes a sandbox and is idempotent.
	Delete(name string) error

	// Exec runs one command inside a running sandbox and captures its output,
	// reporting ErrExecTimeout or ErrExecOutputLimit when those bounds are hit.
	Exec(ctx context.Context, name string, request ExecRequest) (ExecResult, error)
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
// implementation reports them; the transport maps them to 409, 408 and 413.
var (
	ErrNotRunning      = errors.New("sandbox is not running")
	ErrExecTimeout     = errors.New("exec timed out")
	ErrExecOutputLimit = errors.New("exec output limit exceeded")
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
