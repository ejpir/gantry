//go:build linux || darwin

package networkworker

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
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

	// The verifier proves denials; this proves the one allowance the
	// worker's correctness depends on. Go's resolver silently falls back
	// to default nameservers when /etc/resolv.conf is unreadable, which can
	// surface as guest NXDOMAINs in constrained DNS environments.
	snapshot := probeResolverSnapshot()
	report.Notes = append(report.Notes, snapshot)
	fmt.Fprintln(os.Stderr, "network worker:", snapshot)

	if mode != "required" {
		return &report, nil
	}
	failed := report.Failed(RequiredConfinementProperties(report.Platform)...)
	if len(failed) == 0 {
		return &report, nil
	}
	return &report, fmt.Errorf("network worker: required confinement not enforced: %v (notes: %v)", failed, report.Notes)
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
			workerconf.PropLandlock,
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

// probeResolverSnapshot reads the resolver configuration exactly as Go's
// pure resolver would and reports the nameservers it would use. On Linux
// the path is the private-root snapshot; on macOS the literal Seatbelt
// grant.
func probeResolverSnapshot() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Sprintf("resolver snapshot UNREADABLE: %v (resolver will fall back to public DNS)", err)
	}
	var servers []string
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	return fmt.Sprintf("resolver snapshot: %d nameserver(s) %v", len(servers), servers)
}
