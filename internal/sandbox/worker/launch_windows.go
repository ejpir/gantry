package worker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

func launchPlatformProcess(executable string, argv, environment []string, spec LaunchSpec,
	diagnostic *os.File) (*os.Process, map[string]net.Conn, Containment, error) {
	supervisorEnds := make([]net.Conn, 0, len(spec.Channels))
	channelFiles := make([]*os.File, 0, 2*len(spec.Channels))
	transferable := make(map[string]struct{}, len(spec.TransferableChannels))
	for _, name := range spec.TransferableChannels {
		transferable[name] = struct{}{}
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

	// Anonymous pipes use two handles per ordinary logical channel. A channel
	// that must cross into another child uses a directly inherited Winsock
	// handle: DuplicateHandle does not produce a transferable socket, whereas
	// TCPConn.File followed by PROC_THREAD_ATTRIBUTE_HANDLE_LIST does.
	for index, name := range spec.Channels {
		slot := firstWorkerSlot + index
		if _, ok := transferable[name]; ok {
			supervisor, child, err := SocketpairConns()
			if err != nil {
				return nil, nil, nil, fmt.Errorf("worker channel %s: %w", name, err)
			}
			file, err := ConnFile(child)
			_ = child.Close()
			if err != nil {
				_ = supervisor.Close()
				return nil, nil, nil, fmt.Errorf("worker transferable channel %s: %w", name, err)
			}
			supervisorEnds = append(supervisorEnds, supervisor)
			channelFiles = append(channelFiles, file)
			environment = append(environment, "GANTRY_WORKER_HANDLE_"+strconv.Itoa(slot)+"="+
				strconv.FormatUint(uint64(file.Fd()), 10))
			continue
		}
		supervisor, child, err := PipeChannels(1)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("worker channel %s: %w", name, err)
		}
		supervisorEnds = append(supervisorEnds, supervisor[0])
		channelFiles = append(channelFiles, child...)
		environment = append(environment,
			"GANTRY_WORKER_READ_"+strconv.Itoa(slot)+"="+strconv.FormatUint(uint64(child[0].Fd()), 10),
			"GANTRY_WORKER_WRITE_"+strconv.Itoa(slot)+"="+strconv.FormatUint(uint64(child[1].Fd()), 10),
		)
	}

	// Role-specific capabilities use explicit slots and are inherited only
	// through the same exact handle allowlist.
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

	probeDir := ""
	if spec.DiagnosticPath != "" {
		probeDir = filepath.Dir(spec.DiagnosticPath)
	}
	process, containment, err := StartWindowsProcess(executable, argv, environment,
		[]*os.File{diagnostic, diagnostic, diagnostic}, handles, probeDir, spec.Role, spec.Confinement)
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
