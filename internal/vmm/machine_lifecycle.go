package vmm

import (
	"errors"
	"fmt"
	"io"
)

// machinePhase records completed ownership transfers. In particular,
// machineStarting means Run owns the invocation but no backend has been
// published, while machineRunning means the backend owner has been adopted.
type machinePhase uint8

const (
	machinePrepared machinePhase = iota
	machineStarting
	machineRunning
	machineExited
	machineStopping
	machineClosed
)

func (p machinePhase) String() string {
	switch p {
	case machinePrepared:
		return "prepared"
	case machineStarting:
		return "starting"
	case machineRunning:
		return "running"
	case machineExited:
		return "exited"
	case machineStopping:
		return "stopping"
	case machineClosed:
		return "closed"
	default:
		return fmt.Sprintf("machinePhase(%d)", uint8(p))
	}
}

// machineLifecycle is guarded by Machine.resourceMu. Keeping transition
// validation here makes Machine the sole phase owner while allowing resource
// publication and phase changes to share one lock.
type machineLifecycle struct {
	phase   machinePhase
	runDone chan struct{}
}

func (s *machineLifecycle) transition(next machinePhase) error {
	valid := false
	switch s.phase {
	case machinePrepared:
		valid = next == machineStarting || next == machineStopping
	case machineStarting:
		valid = next == machineRunning || next == machineExited || next == machineStopping
	case machineRunning:
		valid = next == machineExited || next == machineStopping
	case machineExited:
		valid = next == machineStopping
	case machineStopping:
		valid = next == machineClosed
	}
	if !valid {
		return fmt.Errorf("vmm: invalid machine transition %s -> %s", s.phase, next)
	}
	s.phase = next
	return nil
}

func (s *machineLifecycle) beginRun() error {
	if s.phase != machinePrepared {
		if s.phase == machineStopping || s.phase == machineClosed {
			return errMachineClosed
		}
		return errMachineAlreadyRun
	}
	if err := s.transition(machineStarting); err != nil {
		return err
	}
	s.runDone = make(chan struct{})
	return nil
}

func (s *machineLifecycle) backendReady() error {
	return s.transition(machineRunning)
}

// beginStop returns the Run completion channel when initialization or vCPU
// execution must be joined. It is idempotent for concurrent shutdown paths;
// Machine.closeOnce still owns the actual resource teardown.
func (s *machineLifecycle) beginStop() <-chan struct{} {
	switch s.phase {
	case machineStarting, machineRunning:
		_ = s.transition(machineStopping)
		return s.runDone
	case machineStopping:
		return s.runDone
	case machinePrepared, machineExited:
		_ = s.transition(machineStopping)
	case machineClosed:
		return nil
	}
	return nil
}

func (s *machineLifecycle) finishRun() error {
	switch s.phase {
	case machineStarting, machineRunning:
		if err := s.transition(machineExited); err != nil {
			return err
		}
	case machineStopping:
		// Close owns the terminal transition after observing runDone.
	default:
		return fmt.Errorf("vmm: Run finished in phase %s", s.phase)
	}
	if s.runDone != nil {
		close(s.runDone)
	}
	return nil
}

func (s *machineLifecycle) finishClose() error {
	return s.transition(machineClosed)
}

func (m *Machine) beginRun() error {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	return m.lifecycle.beginRun()
}

func (m *Machine) finishRun() error {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	return m.lifecycle.finishRun()
}

func (m *Machine) phase() machinePhase {
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	return m.lifecycle.phase
}

// adoptBackend transfers a fully constructed backend resource owner to the
// Machine. The caller retains ownership when this method returns an error.
func (m *Machine) adoptBackend(backend io.Closer) error {
	if backend == nil {
		return errors.New("vmm: nil hypervisor backend")
	}
	m.resourceMu.Lock()
	defer m.resourceMu.Unlock()
	if m.lifecycle.phase == machineStopping || m.lifecycle.phase == machineClosed {
		return errMachineClosed
	}
	if m.lifecycle.phase != machineStarting {
		return errors.New("vmm: hypervisor backend adopted outside startup")
	}
	if err := m.backendOwner.adopt(backend); err != nil {
		return err
	}
	if err := m.lifecycle.backendReady(); err != nil {
		m.backendOwner.take()
		return err
	}
	return nil
}
