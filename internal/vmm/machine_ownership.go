package vmm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ejpir/gantry/internal/virtio"
	"github.com/ejpir/gantry/internal/vmm/devices"
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

type hotMemoryMapper interface {
	MapHotMemory() error
}

// machineBackendOwner is the sole holder of the adopted hypervisor backend.
// Runtime operations receive narrower capabilities and cannot close it.
type machineBackendOwner struct {
	backend io.Closer
}

func (o *machineBackendOwner) adopt(backend io.Closer) error {
	if o.backend != nil {
		return errors.New("vmm: hypervisor backend already attached")
	}
	o.backend = backend
	return nil
}

func (o *machineBackendOwner) take() io.Closer {
	backend := o.backend
	o.backend = nil
	return backend
}

func (o *machineBackendOwner) present() bool { return o.backend != nil }

func (o *machineBackendOwner) hotMemoryMapper() (hotMemoryMapper, bool) {
	mapper, ok := o.backend.(interface{ mapHotMemory() error })
	if !ok {
		return nil, false
	}
	return hotMemoryMapperFunc(mapper.mapHotMemory), true
}

type hotMemoryMapperFunc func() error

func (fn hotMemoryMapperFunc) MapHotMemory() error { return fn() }

// machineResources owns the host capabilities, guest memory, and device
// graph acquired by Prepare. Machine embeds it so backend code can retain its
// compact field access while teardown remains centralized here.
//
// Acquisition is capabilities -> memory -> legacy devices -> virtio devices.
// closePrepared releases those groups in reverse order after the backend and
// all vCPU workers have stopped.
type machineResources struct {
	ram       []byte
	ramShared bool
	mem       *virtio.RAM

	whpxBroker          net.Conn // Windows split-WHPX transport; nil uses in-process WHPX
	whpxBrokerCloseOnce sync.Once
	whpxBrokerCloseErr  error
	whpxMailbox         *os.File
	whpxRequestEvent    *os.File
	whpxReplyEvents     []*os.File
	kvmFD               *os.File // pre-opened /dev/kvm; transferred to the KVM backend at Run

	uart *devices.PL011 // arm64 console (MMIO)
	x86  x86Devices

	virtios        []*virtio.Core
	rootBlkCore    *virtio.Core
	vsockCore      *virtio.Core
	vsock          *virtio.Vsock
	hotMem         *virtio.Mem
	hotMemDeferred bool
}

func (r *machineResources) closeWHPXBroker() error {
	r.whpxBrokerCloseOnce.Do(func() {
		if r.whpxBroker != nil {
			r.whpxBrokerCloseErr = r.whpxBroker.Close()
			r.whpxBroker = nil
		}
	})
	return r.whpxBrokerCloseErr
}

// cancelBackendStartup interrupts broker I/O before a backend owner can be
// published. Other platform setup either has a published backend or unwinds
// without a separately cancellable transport.
func (r *machineResources) cancelBackendStartup() error {
	if err := r.closeWHPXBroker(); err != nil {
		return fmt.Errorf("cancel WHPX broker startup: %w", err)
	}
	return nil
}

type whpxBrokerBorrow interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
}

type whpxBrokerView struct {
	reader      io.Reader
	writer      io.Writer
	setDeadline func(time.Time) error
}

func (v whpxBrokerView) Read(buffer []byte) (int, error)  { return v.reader.Read(buffer) }
func (v whpxBrokerView) Write(buffer []byte) (int, error) { return v.writer.Write(buffer) }
func (v whpxBrokerView) SetDeadline(deadline time.Time) error {
	return v.setDeadline(deadline)
}

// borrowWHPXBroker gives the backend data-plane access without Close. The
// owner-supplied abort callback is the only way a failed backend may revoke
// the transport.
func (m *Machine) borrowWHPXBroker() (whpxBrokerBorrow, func(), error) {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	if m.lifecycle.phase != machineStarting {
		return nil, nil, errMachineClosed
	}
	if m.whpxBroker == nil {
		return nil, nil, errors.New("vmm: WHPX broker transport is unavailable")
	}
	view := whpxBrokerView{reader: m.whpxBroker, writer: m.whpxBroker, setDeadline: m.whpxBroker.SetDeadline}
	return view, func() { _ = m.closeWHPXBroker() }, nil
}

func (r *machineResources) closePrepared() error {
	var errs []error
	for index := len(r.virtios) - 1; index >= 0; index-- {
		if err := r.virtios[index].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	r.virtios = nil
	if err := r.x86.close(); err != nil {
		errs = append(errs, fmt.Errorf("close x86 devices: %w", err))
	}
	r.uart = nil
	r.rootBlkCore = nil
	r.vsockCore = nil
	r.vsock = nil
	r.hotMem = nil
	r.hotMemDeferred = false

	if err := r.releaseRAM(); err != nil {
		errs = append(errs, err)
	}

	closeCapability := func(label string, file **os.File) {
		if *file == nil {
			return
		}
		if err := (*file).Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", label, err))
		}
		*file = nil
	}
	for index := len(r.whpxReplyEvents) - 1; index >= 0; index-- {
		closeCapability("WHPX reply event", &r.whpxReplyEvents[index])
	}
	r.whpxReplyEvents = nil
	closeCapability("WHPX request event", &r.whpxRequestEvent)
	closeCapability("WHPX mailbox", &r.whpxMailbox)
	if err := r.closeWHPXBroker(); err != nil {
		errs = append(errs, fmt.Errorf("close WHPX broker transport: %w", err))
	}
	closeCapability("KVM descriptor", &r.kvmFD)
	return errors.Join(errs...)
}

// releaseRAM runs only after backend and device workers are joined, so no
// goroutine can retain a live access to the mapping.
func (r *machineResources) releaseRAM() error {
	if len(r.ram) == 0 {
		r.ramShared = false
		r.mem = nil
		return nil
	}
	if err := freeGuestRAM(r.ram, r.ramShared); err != nil {
		return fmt.Errorf("release guest RAM: %w", err)
	}
	r.ram = nil
	r.ramShared = false
	r.mem = nil
	return nil
}
