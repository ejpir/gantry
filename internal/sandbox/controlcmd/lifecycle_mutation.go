package controlcmd

import (
	"fmt"

	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// mutateRunningOrStoppedResult serializes a stopped-sandbox configuration
// update against daemon launch. Running mutations remain owned by the daemon;
// after taking the stable launch lock we recheck liveness so a process that won
// the race cannot read an older sandbox.json than the one reported as saved.
func mutateRunningOrStoppedResult[T any](name string, running, stopped func() (T, error)) (T, error) {
	if _, alive := layout.PID(name); alive {
		return running()
	}
	lock, err := layout.HoldLaunchLock(name)
	if err != nil {
		if _, alive := layout.PID(name); alive {
			return running()
		}
		var zero T
		return zero, fmt.Errorf("sandbox %q is launching; retry the update when it is up or fully stopped", name)
	}
	defer func() { _ = lock.Close() }()
	if _, alive := layout.PID(name); alive {
		return running()
	}
	return stopped()
}

func mutateRunningOrStopped(name string, running, stopped func() error) error {
	wrap := func(fn func() error) func() (struct{}, error) {
		return func() (struct{}, error) { return struct{}{}, fn() }
	}
	_, err := mutateRunningOrStoppedResult(name, wrap(running), wrap(stopped))
	return err
}
