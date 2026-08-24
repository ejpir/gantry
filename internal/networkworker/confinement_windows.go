package networkworker

import (
	"fmt"
	"net"
	"runtime"

	"github.com/ejpir/gantry/internal/workerconf"
)

// ApplyConfinement verifies the parent-installed AppContainer and Job before
// constructing the userspace network stack. Unlike other worker roles, this
// role deliberately retains ordinary network socket authority; it is the
// egress-policy enforcement point. Its AppContainer capabilities must not
// restore host filesystem, executable, or child-process authority.
func ApplyConfinement(config Config, _, _ net.Conn) (*workerconf.Report, error) {
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

	spec := workerconf.NetworkSpec(0, "")
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
	if applyErr == nil && len(failed) == 0 {
		return &report, nil
	}
	return &report, fmt.Errorf("network worker: required confinement not enforced: %v (apply: %v; notes: %v)",
		failed, applyErr, report.Notes)
}

// Network creation is intentional for this role, so net-dial is not a denial
// property. The one-process Job makes the exec probe fail, while AppContainer
// identity prevents undelegated filesystem reads and writes.
func RequiredConfinementProperties(string) []string {
	return []string{
		workerconf.PropFSRead,
		workerconf.PropFSWrite,
		workerconf.PropExec,
	}
}
