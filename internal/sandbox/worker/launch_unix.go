//go:build linux || darwin

package worker

import (
	"fmt"
	"net"
	"os"
)

func launchPlatformProcess(executable string, argv, environment []string, spec LaunchSpec,
	diagnostic *os.File) (*os.Process, map[string]net.Conn, Containment, error) {
	supervisor := make(map[string]net.Conn, len(spec.Channels))
	workerEnds := make([]net.Conn, 0, len(spec.Channels))
	cleanupChannels := func() {
		for _, channel := range supervisor {
			_ = channel.Close()
		}
		for _, channel := range workerEnds {
			if channel != nil {
				_ = channel.Close()
			}
		}
	}
	for _, name := range spec.Channels {
		supervisorEnd, workerEnd, err := SocketpairConns()
		if err != nil {
			cleanupChannels()
			return nil, nil, nil, err
		}
		supervisor[name] = supervisorEnd
		workerEnds = append(workerEnds, workerEnd)
	}
	keepSupervisor := false
	defer func() {
		if !keepSupervisor {
			for _, channel := range supervisor {
				_ = channel.Close()
			}
		}
	}()

	channelFiles, err := DupConnFiles(workerEnds...)
	// DupConnFiles takes ownership of every workerEnd on success and failure.
	workerEnds = nil
	if err != nil {
		return nil, nil, nil, fmt.Errorf("worker descriptor table: %w", err)
	}
	defer CloseFiles(channelFiles)

	// ExtraFiles is dense and maps index zero to fd 3. Fixed slots make the
	// descriptor table auditable and keep child entry points independent of
	// ambient paths or environment-provided descriptor numbers.
	nextSlot := firstWorkerSlot + len(channelFiles)
	inherited := make([]*os.File, 0, len(spec.InheritedFiles))
	for index, capability := range spec.InheritedFiles {
		if capability.Slot != nextSlot+index {
			return nil, nil, nil, fmt.Errorf(
				"worker %s Unix inherited slot %d is not dense (want %d)",
				spec.Role, capability.Slot, nextSlot+index)
		}
		inherited = append(inherited, capability.File)
	}
	files := make([]*os.File, 0, firstWorkerSlot+len(channelFiles)+len(inherited))
	files = append(files, diagnostic, diagnostic, diagnostic)
	files = append(files, channelFiles...)
	files = append(files, inherited...)

	start := func(confined bool) (*os.Process, error) {
		sys := SysProcAttr()
		if confined {
			ConfineProcAttr(sys)
		}
		return os.StartProcess(executable, argv, &os.ProcAttr{
			Env:   environment,
			Files: files,
			Sys:   sys,
		})
	}
	confined := spec.Confinement == "auto" || spec.Confinement == "required"
	process, err := start(confined)
	if err != nil && spec.Confinement == "auto" && IsNamespaceUnavailable(err) {
		fmt.Fprintf(os.Stderr, "%s: confined spawn denied (%v); retrying without namespaces\n",
			roleProcessName(spec.Role), err)
		process, err = start(false)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("spawn %s: %w", roleProcessName(spec.Role), err)
	}
	keepSupervisor = true
	return process, supervisor, nil, nil
}
