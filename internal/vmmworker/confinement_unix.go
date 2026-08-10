//go:build linux || darwin

package vmmworker

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

func (rt Runtime) confine(config Config, control, bridge, fdChannel net.Conn, assets Assets) (workerconf.Report, error) {
	report := workerconf.DisabledReport(runtime.GOOS, config.Confinement)
	if err := workerconf.SetFileSizeLimit(config.MaxWritableFileSize); err != nil {
		message := "bound writable disk size: " + err.Error()
		_ = workerproto.WriteMessage(control, BootAck{Error: message, Confinement: report})
		return report, fmt.Errorf("%s", message)
	}
	fileLimitNote := ""
	if config.MaxWritableFileSize != 0 {
		fileLimitNote = fmt.Sprintf("writable file growth capped at %d bytes; disk locks remain supervisor-owned", config.MaxWritableFileSize)
		report.Notes = append(report.Notes, fileLimitNote)
	}
	if config.Confinement == "" || config.Confinement == "off" {
		return report, nil
	}

	spec := workerconf.DefaultSpec(keepFDs(config), config.ConfRoot)
	for _, conn := range []net.Conn{control, bridge, fdChannel, assets.ShareConn, assets.NetConn} {
		if fd, ok := connFD(conn); ok {
			spec.KeepFDExtra = append(spec.KeepFDExtra, fd)
		}
	}
	fmt.Fprintf(os.Stderr, "_vmm-worker: confinement %s: applying (KeepFDs=%d extra=%v ConfRoot=%q)\n",
		config.Confinement, keepFDs(config), spec.KeepFDExtra, config.ConfRoot)
	applied, applyErr := rt.ApplyConfinement(spec)
	if applied != nil {
		report = *applied
		report.Mode = config.Confinement
		if fileLimitNote != "" {
			report.Notes = append(report.Notes, fileLimitNote)
		}
	}
	if applyErr != nil {
		report.Notes = append(report.Notes, "apply: "+applyErr.Error())
	}
	fmt.Fprintf(os.Stderr, "_vmm-worker: confinement applied: %v; verifying\n", report.Notes)
	rt.VerifyConfinement(spec, &report)
	fmt.Fprintf(os.Stderr, "_vmm-worker: confinement verified: fs-read=%s net-dial=%s exec=%s\n",
		report.Property(workerconf.PropFSRead).State,
		report.Property(workerconf.PropNetDial).State,
		report.Property(workerconf.PropExec).State)

	if config.Confinement != "required" {
		return report, nil
	}
	failed := report.Failed(requiredConfinementProperties(report.Platform)...)
	if len(failed) == 0 {
		return report, nil
	}
	message := fmt.Sprintf("process isolation required but confinement not enforced: %v", failed)
	_ = workerproto.WriteMessage(control, BootAck{Error: message, Confinement: report})
	return report, fmt.Errorf("%s", message)
}

func keepFDs(config Config) int {
	count := 10 // fixed fds 0..8 plus the kernel at fd 9
	if config.HasRoot {
		count++
	}
	count += config.NDisksRO + config.NDisks
	if config.HasKVM {
		count++
	}
	return count - 1
}

func requiredConfinementProperties(platform string) []string {
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
