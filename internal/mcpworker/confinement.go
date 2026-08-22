package mcpworker

import (
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/ejpir/gantry/internal/workerconf"
)

func ApplyConfinement(config Config, channels ...net.Conn) (*workerconf.Report, error) {
	mode := config.Confinement
	if mode == "" {
		mode = "auto"
	}
	report := workerconf.DisabledReport(runtime.GOOS, mode)
	if mode == "off" {
		return &report, nil
	}
	if mode != "auto" && mode != "required" {
		return &report, fmt.Errorf("mcp worker: invalid confinement mode %q", mode)
	}
	spec := workerconf.MCPSpec(2, config.ConfRoot)
	for _, conn := range channels {
		if fd, ok := connFD(conn); ok {
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
	failed := report.Failed(RequiredConfinementProperties(runtime.GOOS)...)
	if len(failed) != 0 {
		return &report, fmt.Errorf("mcp worker: required confinement not enforced: %v", failed)
	}
	return &report, nil
}

func RequiredConfinementProperties(platform string) []string {
	required := []string{
		workerconf.PropFSRead,
		workerconf.PropFSWrite,
		workerconf.PropNetDial,
		workerconf.PropExec,
	}
	switch platform {
	case "linux":
		required = append(required,
			workerconf.PropFDTable,
			workerconf.PropSyscall,
			workerconf.PropLandlock,
			workerconf.PropProcEnum,
			workerconf.PropTaskLimit,
		)
	case "darwin":
		required = append(required, workerconf.PropProcEnum, workerconf.PropProcSignal)
	}
	return required
}

func connFD(conn net.Conn) (int, bool) {
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
