package vmmworker

import (
	"fmt"
	"net"
	"runtime"

	"github.com/ejpir/gantry/internal/workerconf"
	"github.com/ejpir/gantry/internal/workerproto"
)

func (rt Runtime) confine(config Config, control, bridge, fdChannel net.Conn, assets Assets) (workerconf.Report, error) {
	report := workerconf.DisabledReport(runtime.GOOS, config.Confinement)
	var roleNotes []string
	if config.NDisks != 0 {
		roleNotes = append(roleNotes,
			"Windows mandatory byte-range lock is worker-owned; sandbox lifetime lock remains supervisor-owned")
	}
	if config.WHPXBroker {
		roleNotes = append(roleNotes,
			"WHPX partition is owned by a separate Job-confined trusted broker; device emulation is AppContainer-confined")
	}
	if config.Confinement == "" || config.Confinement == "off" {
		report.Notes = append(report.Notes, roleNotes...)
		return report, nil
	}

	spec := workerconf.DefaultSpec(0, "")
	applied, applyErr := rt.ApplyConfinement(spec)
	if applied != nil {
		report = *applied
		report.Mode = config.Confinement
	}
	report.Notes = append(report.Notes, roleNotes...)
	if applyErr != nil {
		report.Notes = append(report.Notes, "apply: "+applyErr.Error())
	}
	rt.VerifyConfinement(spec, &report)
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

func requiredConfinementProperties(string) []string {
	return []string{
		workerconf.PropFSRead,
		workerconf.PropFSWrite,
		workerconf.PropNetDial,
		workerconf.PropExec,
	}
}
