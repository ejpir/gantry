package vmm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInterruptRouterDisableDrainsCallbacks(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	router := interruptRouter{}
	router.set(func(int, bool) {
		calls.Add(1)
		close(entered)
		<-release
	})

	raised := make(chan struct{})
	go func() {
		router.raise(1, true)
		close(raised)
	}()
	<-entered
	disabled := make(chan struct{})
	go func() {
		router.disable()
		close(disabled)
	}()
	select {
	case <-disabled:
		t.Fatal("disable returned while an IRQ callback was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-raised:
	case <-time.After(time.Second):
		t.Fatal("IRQ callback did not finish")
	}
	select {
	case <-disabled:
	case <-time.After(time.Second):
		t.Fatal("disable did not finish after callback drained")
	}
	router.raise(2, true)
	router.set(func(int, bool) { calls.Add(1) }) // late backend publication
	router.raise(3, true)
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback count after disable = %d, want 1", got)
	}
}

func writeResourceTestFile(t *testing.T, name string, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestMachineCloseWaitsForBackendInitialization(t *testing.T) {
	m := &Machine{}
	if err := m.beginRun(); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()

	deadline := time.Now().Add(time.Second)
	for {
		m.resourceMu.Lock()
		state := m.lifecycle
		m.resourceMu.Unlock()
		if state == machineStopping {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not enter stopping state")
		}
		runtime.Gosched()
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before Run unwound: %v", err)
	default:
	}
	if err := m.adoptBackend(closeFunc(func() error { return nil })); !errors.Is(err, errMachineClosed) {
		t.Fatalf("backend adoption during Close = %v, want errMachineClosed", err)
	}

	m.finishRun()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after Run unwound")
	}
}

func TestMachineRunLifecycleIsSingleUse(t *testing.T) {
	m := &Machine{}
	if err := m.beginRun(); err != nil {
		t.Fatal(err)
	}
	if err := m.beginRun(); !errors.Is(err, errMachineAlreadyRun) {
		t.Fatalf("second beginRun = %v, want errMachineAlreadyRun", err)
	}
	m.finishRun()
	if err := m.beginRun(); !errors.Is(err, errMachineAlreadyRun) {
		t.Fatalf("beginRun after exit = %v, want errMachineAlreadyRun", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.beginRun(); !errors.Is(err, errMachineClosed) {
		t.Fatalf("beginRun after Close = %v, want errMachineClosed", err)
	}
}

type closeFunc func() error

func (fn closeFunc) Close() error { return fn() }

func TestValidateResources(t *testing.T) {
	maximumVCPUs := MaxSupportedVCPUs()
	for _, tc := range []struct {
		name   string
		memory uint64
		vcpus  int
		ok     bool
	}{
		{name: "minimum", memory: MinMemoryBytes, vcpus: 1, ok: true},
		{name: "maximum", memory: MaxMemoryBytes, vcpus: maximumVCPUs, ok: true},
		{name: "below minimum", memory: MinMemoryBytes - 1, vcpus: 1},
		{name: "above maximum", memory: MaxMemoryBytes + 1, vcpus: 1},
		{name: "zero CPUs", memory: MinMemoryBytes, vcpus: 0},
		{name: "too many CPUs", memory: MinMemoryBytes, vcpus: maximumVCPUs + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateResources(tc.memory, tc.vcpus)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidateResources(%d, %d) = %v, ok=%v", tc.memory, tc.vcpus, err, tc.ok)
			}
		})
	}
}

func TestSupportedVCPUCountUsesHostAndPlatformCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name          string
		hostCPUs      int
		platformLimit int
		want          int
	}{
		{name: "host is smaller", hostCPUs: 12, platformLimit: 64, want: 12},
		{name: "platform is smaller", hostCPUs: 12, platformLimit: 1, want: 1},
		{name: "architectural ceiling", hostCPUs: MaxVCPUs + 10, platformLimit: MaxVCPUs + 20, want: MaxVCPUs},
		{name: "defensive minimum", hostCPUs: 0, platformLimit: 0, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := supportedVCPUCount(tc.hostCPUs, tc.platformLimit); got != tc.want {
				t.Fatalf("supportedVCPUCount(%d, %d) = %d, want %d", tc.hostCPUs, tc.platformLimit, got, tc.want)
			}
		})
	}
}

func TestLoadKernelRejectsOffsetBeyondRAMWithoutPanic(t *testing.T) {
	image := make([]byte, 64)
	binary.LittleEndian.PutUint64(image[0x08:], kernelOff)
	copy(image[0x38:], "ARM\x64")
	f := writeResourceTestFile(t, "Image", image)

	if _, _, err := loadKernel(f, make([]byte, kernelOff-1)); err == nil || !strings.Contains(err.Error(), "too big") {
		t.Fatalf("loadKernel error = %v, want guest-RAM bounds error", err)
	}
}

func TestLoadInitrdRejectsOffsetBeyondRAMWithoutPanic(t *testing.T) {
	f := writeResourceTestFile(t, "initrd", []byte{1})
	if _, _, err := loadInitrd(f, make([]byte, initrdOff-1)); err == nil || !strings.Contains(err.Error(), "too big") {
		t.Fatalf("loadInitrd error = %v, want guest-RAM bounds error", err)
	}
}

func TestRawBootAssetsLoadDirectlyIntoGuestRAM(t *testing.T) {
	image := make([]byte, 4096)
	copy(image[0x38:], "ARM\x64")
	for i := 64; i < len(image); i++ {
		image[i] = byte(i)
	}
	kernel := writeResourceTestFile(t, "Image", image)
	initrdData := []byte("direct initrd payload")
	initrd := writeResourceTestFile(t, "initrd", initrdData)
	ram := make([]byte, initrdOff+uint64(len(initrdData)))

	if _, arch, err := loadKernel(kernel, ram); err != nil || arch != "arm64" {
		t.Fatalf("loadKernel arch=%q err=%v", arch, err)
	}
	if got := ram[kernelOff : kernelOff+uint64(len(image))]; !bytes.Equal(got, image) {
		t.Fatal("kernel bytes were not loaded at the final guest-RAM destination")
	}
	if _, _, err := loadInitrd(initrd, ram); err != nil {
		t.Fatal(err)
	}
	if got := ram[initrdOff:]; !bytes.Equal(got, initrdData) {
		t.Fatalf("initrd bytes = %q, want %q", got, initrdData)
	}
}
