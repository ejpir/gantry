//go:build linux || darwin

package networkworker

import (
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/ejpir/gantry/internal/workerconf"
)

// ApplyConfinement removes ambient authority before the embedded network
// stack is constructed. The worker keeps only its authenticated inherited
// channels; later host sockets must pass the role-specific INET stream/datagram
// policy. An empty mode is the persisted spelling of auto.
func ApplyConfinement(config Config, control, data net.Conn) (*workerconf.Report, error) {
	mode := config.Confinement
	if mode == "" {
		mode = "auto"
	}
	report := workerconf.DisabledReport(runtime.GOOS, mode)
	if mode == "off" {
		return &report, nil
	}
	if mode != "auto" && mode != "required" {
		return &report, fmt.Errorf("network worker: invalid confinement mode %q", mode)
	}

	spec := workerconf.NetworkSpec(2, config.ConfRoot)
	for _, conn := range []net.Conn{control, data} {
		if fd, ok := networkConnFD(conn); ok {
			spec.KeepFDExtra = append(spec.KeepFDExtra, fd)
		}
	}
	applied, applyErr := workerconf.Apply(spec)
	if applied != nil {
		report = *applied
		report.Mode = mode
	}
	if applyErr != nil {
		report.Notes = append(report.Notes, "apply: "+applyErr.Error())
	}
	workerconf.Verify(spec, &report)

	if mode != "required" {
		return &report, nil
	}
	failed := report.Failed(RequiredConfinementProperties(report.Platform)...)
	if len(failed) == 0 {
		return &report, nil
	}
	return &report, fmt.Errorf("network worker: required confinement not enforced: %v", failed)
}

// RequiredConfinementProperties excludes net-dial: creating host TCP/UDP
// sockets is this worker's purpose, not a boundary it can claim. Filesystem,
// executable, and cross-process access remain mandatory denials.
func RequiredConfinementProperties(platform string) []string {
	required := []string{
		workerconf.PropFSRead,
		workerconf.PropFSWrite,
		workerconf.PropExec,
	}
	switch platform {
	case "linux":
		required = append(required,
			workerconf.PropFDTable,
			workerconf.PropSyscall,
			workerconf.PropProcEnum,
			workerconf.PropTaskLimit,
		)
	case "darwin":
		required = append(required, workerconf.PropProcEnum, workerconf.PropProcSignal)
	}
	return required
}

func networkConnFD(conn net.Conn) (int, bool) {
	rawConn, ok := conn.(syscall.Conn)
	if !ok || rawConn == nil {
		return 0, false
	}
	raw, err := rawConn.SyscallConn()
	if err != nil {
		return 0, false
	}
	fd := -1
	if err := raw.Control(func(value uintptr) { fd = int(value) }); err != nil || fd < 0 {
		return 0, false
	}
	return fd, true
}
