package sandbox

import (
	"fmt"
	"net"
	"os"
)

func spawnNetWorkerProcess(stderrPath, confinement string) (control, data net.Conn, proc *os.Process, diagnostics *boundedLogPipe, err error) {
	_ = confinement
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	channels, childFiles, err := workerPipeChannels(2)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keepChannels := false
	defer func() {
		closeFiles(childFiles)
		if !keepChannels {
			for _, channel := range channels {
				_ = channel.Close()
			}
		}
	}()
	childHandles, err := inheritableHandles(childFiles)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer clearInheritedHandles(childHandles)

	argv := []string{exe, "_net-worker"}
	env := workerPipeEnv(networkWorkerEnv(), childFiles, 3)
	if netWorkerSpawnHook != nil {
		netWorkerSpawnHook(&argv, &env)
	}
	workerLog, err := newBoundedLogPipe(stderrPath)
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
		Sys:   windowsWorkerSysProcAttr(0, childHandles),
	})
	workerLog.ReleaseWriter()
	closeFiles(childFiles)
	childFiles = nil
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("spawn net-worker: %w", err)
	}
	keepLog = true
	keepChannels = true
	return channels[0], channels[1], proc, workerLog, nil
}
