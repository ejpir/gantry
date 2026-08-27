package vmm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"sync"

	"github.com/ejpir/gantry/internal/virtio"
)

const (
	// MinMemoryBytes keeps every fixed boot structure address inside RAM.
	// Individual loaders still validate the complete image range.
	MinMemoryBytes = initrdOff + 1
	MaxMemoryBytes = 1 << 40 // 1 TiB
	// MaxVCPUs is the VMM-wide architectural ceiling. The ARM memory map can
	// fit 251 GIC redistributors below the first virtio-mmio device; the x86
	// topology uses the same conservative ceiling. Hosts normally expose a
	// smaller limit through MaxSupportedVCPUs.
	MaxVCPUs = 251
)

// MaxSupportedVCPUs returns the number of vCPUs this host/backend can use.
// Avoid offering more virtual processors than the host can schedule, while
// retaining any backend-specific constraints.
func MaxSupportedVCPUs() int {
	return supportedVCPUCount(runtime.NumCPU(), platformMaxVCPUs())
}

func supportedVCPUCount(hostCPUs, platformLimit int) int {
	if hostCPUs < 1 {
		hostCPUs = 1
	}
	if platformLimit < 1 {
		platformLimit = 1
	}
	return min(hostCPUs, platformLimit, MaxVCPUs)
}

// ValidateResources rejects resource requests before any large allocation.
// Prepare calls it defensively even when a higher-level caller has already
// validated flags or persisted configuration.
func ValidateResources(memBytes uint64, vcpus int) error {
	switch {
	case memBytes < MinMemoryBytes:
		return fmt.Errorf("memory must be at least %d MiB", (MinMemoryBytes+(1<<20)-1)>>20)
	case memBytes > MaxMemoryBytes:
		return fmt.Errorf("memory must be at most %d MiB", MaxMemoryBytes>>20)
	case memBytes > uint64(maxInt()):
		return fmt.Errorf("memory size %d exceeds this platform's address space", memBytes)
	case vcpus < 1 || vcpus > MaxVCPUs:
		return fmt.Errorf("CPUs must be between 1 and %d", MaxVCPUs)
	}
	if err := validatePlatformResources(vcpus); err != nil {
		return err
	}
	if maximum := MaxSupportedVCPUs(); vcpus > maximum {
		return fmt.Errorf("CPUs must be between 1 and %d on this host", maximum)
	}
	return nil
}

func maxInt() int { return int(^uint(0) >> 1) }

type machineLifecycle uint8

const (
	machinePrepared machineLifecycle = iota
	machineRunning
	machineStopping
	machineExited
	machineClosed
)

// interruptRouter serializes callback publication and native-backend teardown.
// Device goroutines may raise interrupts as soon as Prepare attaches them, so
// a plain function field would race backend startup and could run through a
// closed or reused native descriptor during Close.
type interruptRouter struct {
	mu       sync.RWMutex
	line     func(int, bool)
	disabled bool
}

func (r *interruptRouter) set(line func(int, bool)) {
	r.mu.Lock()
	if !r.disabled {
		r.line = line
	}
	r.mu.Unlock()
}

func (r *interruptRouter) raise(irq int, level bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.line != nil {
		r.line(irq, level)
	}
}

// disable is sticky and waits for callbacks that already loaded the current
// route. A backend racing Close cannot publish a route afterward; once this
// returns, native resources can be released without a late IRQ ioctl.
func (r *interruptRouter) disable() {
	r.mu.Lock()
	r.disabled = true
	r.line = nil
	r.mu.Unlock()
}

// beginStop returns whether a Run invocation must be joined. resourceMu
// serializes every transition; stopping and exited are distinct so Close can
// tell an initializing/running backend from one that has fully unwound.
func (s *machineLifecycle) beginStop() bool {
	wait := *s == machineRunning || *s == machineStopping
	if *s != machineClosed {
		*s = machineStopping
	}
	return wait
}

// releaseRAM runs only after backend and device workers are joined, so no
// goroutine can retain a live access to the mapping.
func (m *Machine) releaseRAM() error {
	if len(m.ram) == 0 {
		return nil
	}
	if err := freeGuestRAM(m.ram, m.ramShared); err != nil {
		return fmt.Errorf("release guest RAM: %w", err)
	}
	m.ram = nil
	m.ramShared = false
	m.mem = nil
	return nil
}

// prepareInputs owns every descriptor-bearing Opts field from the instant
// Prepare is called. A successful constructor or Machine adoption removes a
// capability from this set. Anything left is closed by Prepare's deferred
// cleanup, including inputs it never reached after an early failure.
//
// Filesystem handlers with nil owners, Console, policies, and callbacks are
// borrowed; descriptors and non-nil Filesystem owners are consumed.
type prepareInputs struct {
	files            map[*os.File]string
	diskBackends     map[virtio.BlkBackend]string
	filesystemOwners []ownedFilesystem
	netConn          net.Conn
}

type ownedFilesystem struct {
	tag    string
	closer io.Closer
}

func collectPrepareInputs(o Opts) (*prepareInputs, error) {
	in := &prepareInputs{
		files:            make(map[*os.File]string, 4+len(o.DisksRO)+len(o.Disks)),
		diskBackends:     make(map[virtio.BlkBackend]string, len(o.DiskBackends)),
		filesystemOwners: make([]ownedFilesystem, len(o.Filesystems)),
		netConn:          o.NetConn,
	}
	var errs []error
	claim := func(f *os.File, label string, required bool) {
		if f == nil {
			if required {
				errs = append(errs, fmt.Errorf("vmm: %s descriptor is required", label))
			}
			return
		}
		if previous, exists := in.files[f]; exists {
			errs = append(errs, fmt.Errorf("vmm: %s and %s reuse the same descriptor object", previous, label))
			return
		}
		in.files[f] = label
	}

	claim(o.Kernel, "kernel image", true)
	claim(o.Initrd, "initrd", false)
	claim(o.Rootfs, "rootfs", false)
	claim(o.KVM, "KVM", false)
	claim(o.SharedRAM, "shared guest RAM", false)
	claim(o.WHPXMailbox, "WHPX mailbox section", false)
	claim(o.WHPXRequestEvent, "WHPX request event", false)
	for i, event := range o.WHPXReplyEvents {
		claim(event, fmt.Sprintf("WHPX reply event %d", i), false)
	}
	for i, f := range o.DisksRO {
		claim(f, fmt.Sprintf("read-only disk %d", i), true)
	}
	for i, f := range o.Disks {
		claim(f, fmt.Sprintf("writable disk %d", i), true)
	}
	for i, backend := range o.DiskBackends {
		label := fmt.Sprintf("writable disk backend %d", i)
		if backend == nil {
			errs = append(errs, fmt.Errorf("vmm: %s is required", label))
			continue
		}
		if !reflect.TypeOf(backend).Comparable() {
			errs = append(errs, fmt.Errorf("vmm: %s has non-comparable type %T", label, backend))
			continue
		}
		if previous, exists := in.diskBackends[backend]; exists {
			errs = append(errs, fmt.Errorf("vmm: %s and %s reuse the same backend", previous, label))
			continue
		}
		in.diskBackends[backend] = label
	}
	seenOwners := make(map[io.Closer]int, len(o.Filesystems))
	for i, filesystem := range o.Filesystems {
		owner := filesystem.Owner
		if filesystem.Vhost != nil {
			if owner != nil || filesystem.Handler != nil {
				errs = append(errs, fmt.Errorf("vmm: filesystem %d mixes vhost with handler/owner", i))
			}
			owner = filesystem.Vhost
		}
		if owner == nil {
			continue
		}
		ownerValue := reflect.ValueOf(owner)
		if ownerValue.Kind() == reflect.Pointer && ownerValue.IsNil() {
			errs = append(errs, fmt.Errorf("vmm: filesystem %d has a nil owner", i))
			continue
		}
		if ownerValue.Type().Comparable() {
			if previous, exists := seenOwners[owner]; exists {
				errs = append(errs, fmt.Errorf("vmm: filesystems %d and %d reuse the same owner", previous, i))
				continue
			}
			seenOwners[owner] = i
		}
		in.filesystemOwners[i] = ownedFilesystem{tag: filesystem.Tag, closer: owner}
	}
	return in, errors.Join(errs...)
}

func (in *prepareInputs) takeDiskBackend(backend virtio.BlkBackend) virtio.BlkBackend {
	if backend != nil {
		delete(in.diskBackends, backend)
	}
	return backend
}

func (in *prepareInputs) takeFile(f *os.File) *os.File {
	if f != nil {
		delete(in.files, f)
	}
	return f
}

func (in *prepareInputs) closeFile(f *os.File) error {
	if f == nil {
		return nil
	}
	label, owned := in.files[f]
	if !owned {
		return nil
	}
	delete(in.files, f)
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", label, err)
	}
	return nil
}

func (in *prepareInputs) takeNetConn() net.Conn {
	conn := in.netConn
	in.netConn = nil
	return conn
}

func (in *prepareInputs) takeFilesystem(index int) {
	in.filesystemOwners[index].closer = nil
}

func (in *prepareInputs) Close() error {
	var errs []error
	for f, label := range in.files {
		if err := f.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", label, err))
		}
		delete(in.files, f)
	}
	for backend, label := range in.diskBackends {
		if err := backend.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", label, err))
		}
		delete(in.diskBackends, backend)
	}
	for index := range in.filesystemOwners {
		filesystem := &in.filesystemOwners[index]
		if filesystem.closer == nil {
			continue
		}
		if err := filesystem.closer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close filesystem %q: %w", filesystem.tag, err))
		}
		filesystem.closer = nil
	}
	if in.netConn != nil {
		if err := in.netConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close network connection: %w", err))
		}
		in.netConn = nil
	}
	return errors.Join(errs...)
}

var errMachineClosed = errors.New("vmm: machine is closed")
var errMachineAlreadyRun = errors.New("vmm: machine has already been run")

func (m *Machine) beginRun() error {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	if m.lifecycle != machinePrepared {
		if m.lifecycle == machineStopping || m.lifecycle == machineClosed {
			return errMachineClosed
		}
		return errMachineAlreadyRun
	}
	m.lifecycle = machineRunning
	m.runDone = make(chan struct{})
	return nil
}

func (m *Machine) finishRun() {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	switch m.lifecycle {
	case machineRunning:
		m.lifecycle = machineExited
	case machineStopping:
		// Close owns the final transition after it observes runDone.
	default:
		return
	}
	close(m.runDone)
}

// adoptBackend transfers a fully constructed backend resource owner to the
// Machine. The caller retains ownership when this method returns an error.
func (m *Machine) adoptBackend(backend io.Closer) error {
	if backend == nil {
		return errors.New("vmm: nil hypervisor backend")
	}
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	if m.lifecycle == machineStopping || m.lifecycle == machineClosed {
		return errMachineClosed
	}
	if m.lifecycle != machineRunning {
		return errors.New("vmm: hypervisor backend adopted outside Run")
	}
	if m.backend != nil {
		return errors.New("vmm: hypervisor backend already attached")
	}
	m.backend = backend
	return nil
}
