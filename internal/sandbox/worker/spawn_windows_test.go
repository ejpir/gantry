package worker

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ejpir/gantry/internal/workerproto"
)

const appContainerTestChild = "GANTRY_TEST_APPCONTAINER_CHILD"
const appContainerTestDeniedPath = "GANTRY_TEST_APPCONTAINER_DENIED_PATH"
const suspendedTestChild = "GANTRY_TEST_SUSPENDED_CHILD"

func TestWindowsWorkersDoNotAllocateConsoleWindows(t *testing.T) {
	attr := WindowsSysProcAttr(0, nil)
	if attr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("worker creation flags %#x omit CREATE_NO_WINDOW", attr.CreationFlags)
	}
}

func TestWindowsEnvironmentBlockIsSortedAndDoubleTerminated(t *testing.T) {
	block, err := windowsEnvironmentBlock([]string{"z=last", "Alpha=first", "middle=value"})
	if err != nil {
		t.Fatal(err)
	}
	if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatalf("environment block is not double-terminated: %v", block)
	}
	text := windows.UTF16ToString(block[:len(block)-1])
	if !strings.HasPrefix(text, "Alpha=first") {
		t.Fatalf("environment block is not case-insensitively sorted: %q", text)
	}
}

func TestWindowsSuspendedJobLaunch(t *testing.T) {
	if os.Getenv(suspendedTestChild) == "1" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GANTRY_WINDOWS_APPCONTAINER", "0")
	environment := windowsTestEnvironment(suspendedTestChild + "=1")
	process, containment, err := StartWindowsProcess(executable,
		[]string{executable, "-test.run=^TestWindowsSuspendedJobLaunch$"},
		environment, []*os.File{os.Stdin, os.Stdout, os.Stderr}, nil,
		workerproto.RoleVMM, "auto")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = containment.Close() }()
	state, err := process.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if !state.Success() {
		t.Fatalf("suspended Job child %s", state)
	}
}

func TestWindowsRequiredAppContainerLaunch(t *testing.T) {
	testWindowsRequiredAppContainerLaunch(t, workerproto.RoleMCP)
}

func TestWindowsRequiredBrokeredVMMAppContainerLaunch(t *testing.T) {
	testWindowsRequiredAppContainerLaunch(t, workerproto.RoleVMM,
		"GANTRY_WINDOWS_WHPX_BROKER_ACTIVE=1")
}

func testWindowsRequiredAppContainerLaunch(t *testing.T, role workerproto.Role, extra ...string) {
	if os.Getenv(appContainerTestChild) == "1" {
		assertAppContainerChild(t)
		return
	}

	deniedPath := filepath.Join(t.TempDir(), "supervisor-private.txt")
	if err := os.WriteFile(deniedPath, []byte("not delegated"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment := windowsTestEnvironment(append([]string{
		appContainerTestChild + "=1",
		appContainerTestDeniedPath + "=" + deniedPath,
	}, extra...)...)
	process, containment, err := StartWindowsProcess(executable,
		[]string{executable, "-test.run=^" + t.Name() + "$"},
		environment, []*os.File{os.Stdin, os.Stdout, os.Stderr}, nil,
		role, "required")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = containment.Close() }()
	state, err := process.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if !state.Success() {
		t.Fatalf("AppContainer child %s", state)
	}
}

func windowsTestEnvironment(extra ...string) []string {
	environment := append([]string(nil), extra...)
	for _, name := range []string{
		"SystemRoot", "WINDIR", "SystemDrive", "TEMP", "TMP",
		"USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData",
	} {
		if value := os.Getenv(name); value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func assertAppContainerChild(t *testing.T) {
	var enabled uint32
	var returned uint32
	if err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), 29,
		(*byte)(unsafe.Pointer(&enabled)), uint32(unsafe.Sizeof(enabled)), &returned); err != nil {
		t.Fatalf("query TokenIsAppContainer: %v", err)
	}
	if enabled == 0 {
		t.Fatal("worker did not receive an AppContainer token")
	}

	deniedPath := os.Getenv(appContainerTestDeniedPath)
	if _, err := os.ReadFile(deniedPath); err == nil {
		t.Fatalf("AppContainer read supervisor file %s", deniedPath)
	}
	writePath := filepath.Join(filepath.Dir(deniedPath), "appcontainer-write.txt")
	if err := os.WriteFile(writePath, []byte("escape"), 0o600); err == nil {
		_ = os.Remove(writePath)
		t.Fatalf("AppContainer wrote supervisor path %s", writePath)
	}

	probeAddress := os.Getenv(windowsWorkerProbeNetEnv)
	connection, err := net.DialTimeout("tcp4", probeAddress, time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatal("zero-capability AppContainer opened a loopback connection")
	}
	if errors.Is(err, windows.WSAECONNREFUSED) {
		t.Fatalf("zero-capability AppContainer retained socket authority: %v", err)
	}
	networkError, timedOut := err.(net.Error)
	policyTimeout := errors.Is(err, windows.WSAETIMEDOUT) || (timedOut && networkError.Timeout())
	if !errors.Is(err, windows.WSAEACCES) && !policyTimeout {
		t.Fatalf("AppContainer network denial = %v, want WSAEACCES or policy-drop timeout", err)
	}

	command := exec.Command(os.Args[0], "-test.run=^$")
	if err := command.Start(); err == nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("one-process worker Job allowed a child process")
	}
}
