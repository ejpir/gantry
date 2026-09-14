package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ejpir/gantry/api/managerapi"
	"github.com/ejpir/gantry/internal/runvm"
)

var newManagerRunCommand = exec.CommandContext

// RunVM deliberately reuses the real local launcher in a child, preserving its
// pinned descriptors and share/vsock checks without running a VM in the manager.
func (managerLifecycle) RunVM(ctx context.Context, request managerapi.RunVMRequest) (managerapi.ExecResult, error) {
	if err := runvm.Validate(request); err != nil {
		return managerapi.ExecResult{}, err
	}
	self, err := os.Executable()
	if err != nil {
		return managerapi.ExecResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(request.TimeoutSeconds)*time.Second)
	defer cancel()
	cmd := newManagerRunCommand(ctx, self, runvm.Args(request)...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(request.Stdin)
	output := &runConsole{limit: request.MaxOutputBytes}
	cmd.Stdout, cmd.Stderr = output, output
	err = cmd.Run() // CommandContext kills and reaps the VM process on cancellation.
	result := output.result()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.ExitCode = 124
		return result, nil
	case ctx.Err() != nil:
		result.ExitCode = 130
		return result, nil
	case err == nil:
		return result, nil
	default:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			result.ExitCode = exit.ExitCode()
			if result.ExitCode < 0 {
				result.ExitCode = 1
			}
			return result, nil
		}
		return result, fmt.Errorf("launch remote VM helper: %w", err)
	}
}

// Always drain the console even after its cap, so a noisy guest cannot block
// the VM or grow manager memory. The operation stores at most 64 KiB.
type runConsole struct {
	mu        sync.Mutex
	limit     int
	output    []byte
	truncated bool
}

func (w *runConsole) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := min(len(p), max(0, w.limit-len(w.output)))
	w.output = append(w.output, p[:n]...)
	w.truncated = w.truncated || n < len(p)
	return len(p), nil
}
func (w *runConsole) result() managerapi.ExecResult {
	w.mu.Lock()
	defer w.mu.Unlock()
	return managerapi.ExecResult{Output: string(w.output), Truncated: w.truncated}
}
