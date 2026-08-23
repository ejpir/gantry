package worker

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

func launchPlatformProcess(executable string, argv, environment []string, spec LaunchSpec,
	diagnostic *os.File) (*os.Process, map[string]net.Conn, Containment, error) {
	supervisorEnds, channelFiles, err := PipeChannels(len(spec.Channels))
	if err != nil {
		return nil, nil, nil, err
	}
	keepSupervisor := false
	defer func() {
		CloseFiles(channelFiles)
		if !keepSupervisor {
			for _, channel := range supervisorEnds {
				_ = channel.Close()
			}
		}
	}()

	// Anonymous pipes use two handles per logical channel but retain the same
	// child slot numbering as Unix descriptors. Role-specific file capabilities
	// use explicit slots and are inherited only through the handle allowlist.
	environment = PipeEnv(environment, channelFiles, firstWorkerSlot)
	inheritedFiles := make([]*os.File, 0, len(spec.InheritedFiles))
	for _, capability := range spec.InheritedFiles {
		environment = append(environment, "GANTRY_WORKER_HANDLE_"+strconv.Itoa(capability.Slot)+"="+
			strconv.FormatUint(uint64(capability.File.Fd()), 10))
		inheritedFiles = append(inheritedFiles, capability.File)
	}
	handleFiles := append(append([]*os.File{}, channelFiles...), inheritedFiles...)
	handles, err := InheritableHandles(handleFiles)
	if err != nil {
		return nil, nil, nil, err
	}
	defer ClearInheritedHandles(handles)

	process, containment, err := StartWindowsProcess(executable, argv, environment,
		[]*os.File{diagnostic, diagnostic, diagnostic}, handles, spec.Role, spec.Confinement)
	// CreateProcess has duplicated the child pipe ends. Closing these copies is
	// what makes process death produce EOF on the supervisor channels.
	CloseFiles(channelFiles)
	channelFiles = nil
	if err != nil {
		return nil, nil, nil, fmt.Errorf("spawn %s: %w", roleProcessName(spec.Role), err)
	}
	channels := make(map[string]net.Conn, len(spec.Channels))
	for index, name := range spec.Channels {
		channels[name] = supervisorEnds[index]
	}
	keepSupervisor = true
	return process, channels, containment, nil
}
