package networker

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/sandbox/worker"
)

func spawnNetWorkerProcess(stderrPath, confinement string) (control, data net.Conn, proc *os.Process, diagnostics *boundedlog.Pipe, err error) {
	_ = confinement
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	channels, childFiles, err := worker.PipeChannels(2)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keepChannels := false
	defer func() {
		worker.CloseFiles(childFiles)
		if !keepChannels {
			for _, channel := range channels {
				_ = channel.Close()
			}
		}
	}()
	childHandles, err := worker.InheritableHandles(childFiles)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer worker.ClearInheritedHandles(childHandles)

	argv := []string{exe, "_net-worker"}
	env := worker.PipeEnv(workerEnv(), childFiles, 3)
	workerLog, err := boundedlog.NewPipe(stderrPath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open network worker log broker: %w", err)
	}
	keepLog := false
	defer func() {
		if !keepLog {
			_ = workerLog.Close()
		}
	}()
	diagnostic := workerLog.Writer()
	proc, err = os.StartProcess(exe, argv, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{diagnostic, diagnostic, diagnostic},
		Sys:   worker.WindowsSysProcAttr(0, childHandles),
	})
	workerLog.ReleaseWriter()
	worker.CloseFiles(childFiles)
	childFiles = nil
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("spawn net-worker: %w", err)
	}
	keepLog = true
	keepChannels = true
	return channels[0], channels[1], proc, workerLog, nil
}
