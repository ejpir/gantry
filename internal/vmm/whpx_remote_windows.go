//go:build windows

package vmm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/ejpir/gantry/internal/vmm/boot"
	"github.com/ejpir/gantry/internal/vmm/devices"
	"github.com/ejpir/gantry/internal/workerproto"
)

type whpxRemoteBackend struct {
	m         *Machine
	conn      net.Conn
	mailboxes *whpxMailboxView

	writeMu   sync.Mutex
	commandID atomic.Uint64
	pendingMu sync.Mutex
	pending   map[uint64]chan error

	closeOnce   sync.Once
	doneOnce    sync.Once
	done        chan struct{}
	mailboxDone chan struct{}
	errMu       sync.Mutex
	err         error
}

func runBrokeredWHPX(m *Machine) error {
	if !m.ramShared || m.whpxToken == "" {
		return fmt.Errorf("brokered WHPX requires shared RAM and an authenticated peer token")
	}
	if os.Getenv("GANTRY_WHPX_PIC") != "" {
		return fmt.Errorf("brokered WHPX does not support the experimental PIC path")
	}
	mailboxes, err := mapWHPXMailboxView(m.whpxMailbox, m.whpxRequestEvent, m.whpxReplyEvents, m.vcpus)
	if err != nil {
		return err
	}
	backend := &whpxRemoteBackend{
		m: m, conn: m.whpxBroker, mailboxes: mailboxes,
		pending: make(map[uint64]chan error), done: make(chan struct{}), mailboxDone: make(chan struct{}),
	}
	defer func() { _ = mailboxes.close() }()
	regions := m.ramRegions()
	initial := regions
	var hot *whpxBrokerRegion
	if m.hotMemDeferred {
		initial = regions[:1]
		candidate := brokerRegion(regions[1])
		hot = &candidate
	}
	setup := whpxBrokerSetup{VCPUs: m.vcpus, Entry: m.entry, Hot: hot}
	for _, region := range initial {
		setup.Initial = append(setup.Initial, brokerRegion(region))
	}
	if err := backend.write(whpxBrokerEnvelope{Type: "setup", Token: m.whpxToken, Setup: &setup}); err != nil {
		return fmt.Errorf("send WHPX broker setup: %w", err)
	}
	var ack whpxBrokerEnvelope
	if err := workerproto.ReadMessage(backend.conn, &ack); err != nil {
		return fmt.Errorf("read WHPX broker setup: %w", err)
	}
	if ack.Type != "setup-ok" {
		if ack.Error == "" {
			ack.Error = "malformed setup acknowledgement"
		}
		return fmt.Errorf("WHPX broker setup: %s", ack.Error)
	}

	m.x86.ioapic = devices.NewIOAPIC(uint32(m.vcpus+1), func(dest, vector uint32, level bool) {
		if err := backend.write(whpxBrokerEnvelope{Type: "interrupt", Interrupt: &whpxBrokerInterrupt{
			Destination: dest, Vector: vector, Level: level,
		}}); err != nil {
			backend.fail(fmt.Errorf("send WHPX interrupt: %w", err))
		}
	})
	m.interrupts.set(func(irq int, level bool) { m.x86.ioapic.Raise(boot.ISAIRQGSI(irq), level) })
	if err := m.adoptBackend(backend); err != nil {
		_ = backend.Close()
		return err
	}

	fmt.Printf("booting guest under brokered WHPX/x86-64 (%d vCPU max)\n", m.vcpus)
	fmt.Println("------------------------------------------------")
	if m.consoleStdin {
		go m.x86.uartIO.StdinPump(m.stdinDone)
		defer close(m.stdinDone)
	}
	m.bootTracer().start("vCPU entered brokered WHPX")
	go backend.mailboxLoop()
	result := backend.readLoop()
	<-backend.mailboxDone
	return result
}

func brokerRegion(region boot.RAMRegion) whpxBrokerRegion {
	return whpxBrokerRegion{GuestBase: region.GuestBase, HostOffset: region.HostOffset, Size: region.Size}
}

func (backend *whpxRemoteBackend) readLoop() error {
	for {
		var message whpxBrokerEnvelope
		if err := workerproto.ReadMessage(backend.conn, &message); err != nil {
			backend.finish(fmt.Errorf("WHPX broker channel: %w", err))
			return backend.result()
		}
		switch message.Type {
		case "command-reply":
			backend.pendingMu.Lock()
			waiter := backend.pending[message.ID]
			delete(backend.pending, message.ID)
			backend.pendingMu.Unlock()
			if waiter == nil {
				backend.fail(fmt.Errorf("unknown WHPX command reply %d", message.ID))
				continue
			}
			if message.Error != "" {
				waiter <- fmt.Errorf("%s", message.Error)
			} else {
				waiter <- nil
			}
		case "done":
			if message.Error != "" {
				backend.setError(fmt.Errorf("WHPX broker: %s", message.Error))
			}
			backend.finish(nil)
			return backend.result()
		default:
			backend.fail(fmt.Errorf("unknown WHPX broker message %q", message.Type))
		}
	}
}

func (backend *whpxRemoteBackend) mailboxLoop() {
	defer close(backend.mailboxDone)
	if backend.m.vcpus == 1 {
		backend.mailboxDispatch(nil)
		return
	}

	// Keep one long-lived handler per vCPU. Creating a goroutine for every
	// MMIO exit adds measurable scheduler and allocation overhead to the boot
	// path, while fixed workers preserve SMP device concurrency.
	queues := make([]chan whpxBrokerExit, backend.m.vcpus)
	var handlers sync.WaitGroup
	for vp := range queues {
		queues[vp] = make(chan whpxBrokerExit, 1)
		handlers.Add(1)
		go func(queue <-chan whpxBrokerExit) {
			defer handlers.Done()
			for exit := range queue {
				backend.handleMailboxExit(exit)
			}
		}(queues[vp])
	}
	backend.mailboxDispatch(queues)
	for _, queue := range queues {
		close(queue)
	}
	handlers.Wait()
}

func (backend *whpxRemoteBackend) mailboxDispatch(queues []chan whpxBrokerExit) {
	for {
		if err := backend.mailboxes.waitRequest(); err != nil {
			backend.fail(err)
			return
		}
		select {
		case <-backend.done:
			return
		default:
		}
		exits, err := backend.mailboxes.claimRequests()
		if err != nil {
			backend.fail(err)
			return
		}
		for _, exit := range exits {
			if queues == nil {
				backend.handleMailboxExit(exit)
			} else {
				queues[exit.VCPU] <- exit
			}
		}
	}
}

func (backend *whpxRemoteBackend) handleMailboxExit(exit whpxBrokerExit) {
	reply, err := backend.handleExit(exit)
	if err != nil {
		reply = whpxBrokerReply{ID: exit.ID, Stop: true, Error: err.Error()}
		backend.setError(err)
	}
	if err := backend.mailboxes.respond(exit.VCPU, reply); err != nil {
		backend.fail(err)
	}
}

func (backend *whpxRemoteBackend) handleExit(exit whpxBrokerExit) (whpxBrokerReply, error) {
	if exit.ID == 0 || exit.VCPU >= uint32(backend.m.vcpus) || len(exit.Context) != whvExitContextSize {
		return whpxBrokerReply{ID: exit.ID}, fmt.Errorf("invalid WHPX exit envelope")
	}
	reason := binary.LittleEndian.Uint32(exit.Context)
	switch reason {
	case whvExitMemoryAccess:
		return backend.handleMMIOExit(exit)
	case whvExitIoPort:
		return backend.handleIOExit(exit)
	default:
		return whpxBrokerReply{ID: exit.ID}, fmt.Errorf("unexpected brokered WHPX exit reason %#x", reason)
	}
}

func (backend *whpxRemoteBackend) handleMMIOExit(exit whpxBrokerExit) (whpxBrokerReply, error) {
	if len(exit.GPRs) != 16 {
		return whpxBrokerReply{ID: exit.ID}, fmt.Errorf("MMIO exit has %d GPRs", len(exit.GPRs))
	}
	context := exit.Context
	instruction := context[52 : 52+15]
	gpa := binary.LittleEndian.Uint64(context[72:])
	op, err := devices.DecodeMMIO(instruction)
	if err != nil {
		return whpxBrokerReply{ID: exit.ID}, fmt.Errorf("MMIO @ %#x: %w", gpa, err)
	}
	if !op.ImmOK && (op.Reg < 0 || op.Reg >= len(exit.GPRs)) {
		return whpxBrokerReply{ID: exit.ID}, fmt.Errorf("MMIO register %d out of range", op.Reg)
	}
	var registerValue uint64
	if op.Reg >= 0 {
		registerValue = exit.GPRs[op.Reg]
	}
	getReg := func(int) uint64 { return registerValue }
	setReg := func(_ int, value uint64) { registerValue = value }
	devRead := func(width int) uint64 {
		var value uint64
		for offset := 0; offset < width; offset += 4 {
			value |= uint64(backend.m.handleMMIO(false, gpa+uint64(offset), nil, 4)) << (8 * offset)
		}
		return value
	}
	devWrite := func(width int, value uint64) {
		var raw [8]byte
		binary.LittleEndian.PutUint64(raw[:], value)
		for offset := 0; offset < width; offset += 4 {
			backend.m.handleMMIO(true, gpa+uint64(offset), raw[offset:offset+4], 4)
		}
	}
	devices.ApplyMMIO(op, getReg, setReg, devRead, devWrite)
	rip := binary.LittleEndian.Uint64(context[32:]) + uint64(op.Length)
	reply := whpxBrokerReply{ID: exit.ID, RegisterNames: []uint32{whvRegRip}, RegisterValues: []uint64{rip}}
	if !op.IsWrite {
		reply.RegisterNames = []uint32{uint32(op.Reg), whvRegRip}
		reply.RegisterValues = []uint64{registerValue, rip}
	}
	return reply, nil
}

func (backend *whpxRemoteBackend) handleIOExit(exit whpxBrokerExit) (whpxBrokerReply, error) {
	context := exit.Context
	accessInfo := binary.LittleEndian.Uint32(context[68:])
	isWrite := accessInfo&1 != 0
	size := int((accessInfo >> 1) & 7)
	port := binary.LittleEndian.Uint16(context[72:])
	rax := binary.LittleEndian.Uint64(context[80:])
	if accessInfo&0x30 != 0 {
		return whpxBrokerReply{ID: exit.ID}, fmt.Errorf("string I/O to port %#x", port)
	}
	if isWrite && (port == 0xcf9 || (port == 0x64 && byte(rax) == 0xfe)) {
		backend.m.stdoutFlush()
		fmt.Println("\n------------------------------------------------")
		fmt.Println("guest rebooted (reset port); exiting")
		backend.setError(ErrGuestReset)
		return whpxBrokerReply{ID: exit.ID, Stop: true}, nil
	}
	instructionLength := int(context[10] & 0x0f)
	if instructionLength == 0 {
		instructionLength = int(context[48])
	}
	if instructionLength == 0 {
		return whpxBrokerReply{ID: exit.ID}, fmt.Errorf("I/O exit at RIP %#x has zero instruction length", binary.LittleEndian.Uint64(context[32:]))
	}
	rip := binary.LittleEndian.Uint64(context[32:]) + uint64(instructionLength)
	if isWrite {
		backend.m.handleIO(true, port, uint32(rax), size)
		return whpxBrokerReply{ID: exit.ID, RegisterNames: []uint32{whvRegRip}, RegisterValues: []uint64{rip}}, nil
	}
	value := backend.m.handleIO(false, port, 0, size)
	switch size {
	case 1:
		rax = rax&^0xff | uint64(byte(value))
	case 2:
		rax = rax&^0xffff | uint64(uint16(value))
	default:
		rax = uint64(value)
	}
	return whpxBrokerReply{ID: exit.ID,
		RegisterNames: []uint32{whvRegRax, whvRegRip}, RegisterValues: []uint64{rax, rip}}, nil
}

func (backend *whpxRemoteBackend) mapHotMemory() error {
	regions := backend.m.ramRegions()
	if len(regions) != 2 || backend.m.hotMem == nil {
		return fmt.Errorf("map brokered hot memory: invalid memory layout")
	}
	region := regions[1]
	if err := commitGuestRAM(backend.m.ram, region.HostOffset, region.Size); err != nil {
		return err
	}
	id := backend.commandID.Add(1)
	waiter := make(chan error, 1)
	backend.pendingMu.Lock()
	backend.pending[id] = waiter
	backend.pendingMu.Unlock()
	if err := backend.write(whpxBrokerEnvelope{Type: "map-hot", ID: id}); err != nil {
		backend.pendingMu.Lock()
		delete(backend.pending, id)
		backend.pendingMu.Unlock()
		return err
	}
	select {
	case err := <-waiter:
		return err
	case <-backend.done:
		return backend.result()
	}
}

func (backend *whpxRemoteBackend) Close() error {
	backend.closeOnce.Do(func() {
		_ = backend.write(whpxBrokerEnvelope{Type: "close"})
	})
	return nil
}

func (backend *whpxRemoteBackend) write(message whpxBrokerEnvelope) error {
	backend.writeMu.Lock()
	defer backend.writeMu.Unlock()
	return workerproto.WriteMessage(backend.conn, message)
}

func (backend *whpxRemoteBackend) fail(err error) {
	backend.setError(err)
	_ = backend.conn.Close()
}

func (backend *whpxRemoteBackend) setError(err error) {
	if err == nil {
		return
	}
	backend.errMu.Lock()
	if backend.err == nil {
		backend.err = err
	} else if !errors.Is(backend.err, err) {
		backend.err = errors.Join(backend.err, err)
	}
	backend.errMu.Unlock()
}

func (backend *whpxRemoteBackend) finish(err error) {
	backend.setError(err)
	backend.doneOnce.Do(func() {
		close(backend.done)
		if backend.mailboxes != nil {
			backend.mailboxes.signalRequest()
		}
	})
}

func (backend *whpxRemoteBackend) result() error {
	backend.errMu.Lock()
	defer backend.errMu.Unlock()
	return backend.err
}
