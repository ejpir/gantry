package worker

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/ejpir/gantry/internal/workerproto"
)

// SocketpairConns returns a connected loopback pair. Windows has no
// socketpair syscall, but a connected TCP pair has the byte-stream and handle
// transfer properties required by the private worker channels.
func SocketpairConns() (a, b net.Conn, err error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, fmt.Errorf("worker loopback listen: %w", err)
	}
	defer func() { _ = listener.Close() }()

	dialed, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return nil, nil, fmt.Errorf("worker loopback dial: %w", err)
	}
	accepted, err := listener.AcceptTCP()
	if err != nil {
		_ = dialed.Close()
		return nil, nil, fmt.Errorf("worker loopback accept: %w", err)
	}
	return accepted, dialed, nil
}

func PipeChannels(count int) (supervisor []net.Conn, childFiles []*os.File, err error) {
	cleanup := func() {
		for _, conn := range supervisor {
			_ = conn.Close()
		}
		CloseFiles(childFiles)
	}
	for index := 0; index < count; index++ {
		childRead, supervisorWrite, pipeErr := os.Pipe()
		if pipeErr != nil {
			cleanup()
			return nil, nil, fmt.Errorf("worker channel %d input pipe: %w", index, pipeErr)
		}
		supervisorRead, childWrite, pipeErr := os.Pipe()
		if pipeErr != nil {
			_ = childRead.Close()
			_ = supervisorWrite.Close()
			cleanup()
			return nil, nil, fmt.Errorf("worker channel %d output pipe: %w", index, pipeErr)
		}
		supervisor = append(supervisor, workerproto.NewPipeConn(supervisorRead, supervisorWrite))
		childFiles = append(childFiles, childRead, childWrite)
	}
	return supervisor, childFiles, nil
}

func PipeEnv(base []string, childFiles []*os.File, firstSlot int) []string {
	env := append([]string(nil), base...)
	for index := 0; index < len(childFiles)/2; index++ {
		slot := strconv.Itoa(firstSlot + index)
		env = append(env,
			"GANTRY_WORKER_READ_"+slot+"="+strconv.FormatUint(uint64(childFiles[2*index].Fd()), 10),
			"GANTRY_WORKER_WRITE_"+slot+"="+strconv.FormatUint(uint64(childFiles[2*index+1].Fd()), 10),
		)
	}
	return env
}

func ConnFile(conn net.Conn) (*os.File, error) {
	type filer interface{ File() (*os.File, error) }
	filerConn, ok := conn.(filer)
	if !ok {
		return nil, fmt.Errorf("conn %T cannot expose its Windows socket", conn)
	}
	return filerConn.File()
}

// InheritableHandles marks the exact capability list passed through
// PROC_THREAD_ATTRIBUTE_HANDLE_LIST. In particular, socket handles must be
// inherited directly: DuplicateHandle produces a kernel handle that is not a
// usable Winsock socket in the child. The caller clears the temporary inherit
// bits immediately after CreateProcess returns.
func InheritableHandles(files []*os.File) ([]syscall.Handle, error) {
	handles := make([]syscall.Handle, 0, len(files))
	for index, file := range files {
		if file == nil {
			ClearInheritedHandles(handles)
			return nil, fmt.Errorf("inherited handle %d is nil", index)
		}
		handle := syscall.Handle(file.Fd())
		if err := windows.SetHandleInformation(windows.Handle(handle), windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			ClearInheritedHandles(handles)
			return nil, fmt.Errorf("mark inherited handle %d: %w", index, err)
		}
		handles = append(handles, handle)
	}
	return handles, nil
}

func ClearInheritedHandles(handles []syscall.Handle) {
	for _, handle := range handles {
		_ = windows.SetHandleInformation(windows.Handle(handle), windows.HANDLE_FLAG_INHERIT, 0)
	}
}

// WindowsSysProcAttr keeps re-executed worker processes in the
// supervisor's background process tree without allocating a console window.
// All worker input and diagnostics use the explicit inherited handles below,
// so the workers do not need a console even when gantry itself is a console
// executable launched from the TUI.
func WindowsSysProcAttr(token windows.Token, handles []syscall.Handle) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Token:                      syscall.Token(token),
		AdditionalInheritedHandles: handles,
		CreationFlags:              windows.CREATE_NO_WINDOW,
	}
}

// HandleEnv publishes raw inheritable handle values to the child under
// GANTRY_WORKER_HANDLE_<slot>, the Windows counterpart to inherited fds.
func HandleEnv(base []string, files []*os.File, firstSlot int) []string {
	env := append([]string(nil), base...)
	for index, file := range files {
		env = append(env, "GANTRY_WORKER_HANDLE_"+strconv.Itoa(firstSlot+index)+"="+
			strconv.FormatUint(uint64(file.Fd()), 10))
	}
	return env
}
