//go:build linux || darwin

package networker

import (
	"fmt"
	"net"
	"os"

	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/sandbox/worker"
)

// spawnNetWorkerProcess re-executes this exact binary in the hidden
// _net-worker role with the control (fd 3) and data (fd 4) socketpair
// ends as its only inherited descriptors. The role argument carries no
// authority — the inherited channels do — and the environment is an
// explicit allowlist so no daemon-held secret leaks into the child.
// stderrPath, when non-empty, receives a bounded worker diagnostic stream.
// The child inherits only a write-only pipe; the supervisor retains sole
// ownership of the regular file.
func spawnNetWorkerProcess(stderrPath, confinement string) (control, data net.Conn, cmd *os.Process, diagnostics *boundedlog.Pipe, err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("worker re-exec path: %w", err)
	}
	ctrlSup, ctrlWrk, err := worker.SocketpairConns()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	dataSup, dataWrk, err := worker.SocketpairConns()
	if err != nil {
		_ = ctrlSup.Close()
		_ = ctrlWrk.Close()
		return nil, nil, nil, nil, err
	}
	keepSupervisorEnds := false
	defer func() {
		if !keepSupervisorEnds {
			_ = ctrlSup.Close()
			_ = dataSup.Close()
		}
	}()
	argv := []string{exe, "_net-worker"}
	env := workerEnv()
	// ExtraFiles needs *os.File handles that survive exec: dup the conns
	// back to plain files. The child's fd numbering is 3,4 in slice order.
	childFiles, err := worker.DupConnFiles(ctrlWrk, dataWrk)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("worker descriptor table: %w", err)
	}
	defer worker.CloseFiles(childFiles)

	workerLog, err := boundedlog.NewPipe(stderrPath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open network worker log broker: %w", err)
	}
	keepWorkerLog := false
	defer func() {
		if !keepWorkerLog {
			_ = workerLog.Close()
		}
	}()
	diagnostic := workerLog.Writer()
	start := func(namespaced bool) (*os.Process, error) {
		sys := worker.SysProcAttr()
		if namespaced {
			worker.ConfineProcAttr(sys)
		}
		return os.StartProcess(exe, argv, &os.ProcAttr{
			Env: env,
			// fd 0 cannot expose the daemon's secrets handshake; fd 1/2 cannot
			// seek, truncate, or grow daemon.log/worker-net.log directly.
			Files: []*os.File{diagnostic, diagnostic, diagnostic, childFiles[0], childFiles[1]},
			Sys:   sys,
		})
	}
	namespaced := confinement != "off"
	proc, err := start(namespaced)
	if err != nil && confinement == "auto" && worker.IsNamespaceUnavailable(err) {
		fmt.Fprintf(os.Stderr, "network worker: confined spawn denied (%v); retrying without namespaces\n", err)
		proc, err = start(false)
	}
	workerLog.ReleaseWriter()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("spawn net-worker: %w", err)
	}
	// The drain goroutine self-owns the file until process EOF.
	keepWorkerLog = true
	keepSupervisorEnds = true
	return ctrlSup, dataSup, proc, workerLog, nil
}
