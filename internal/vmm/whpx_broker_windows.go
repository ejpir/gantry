//go:build windows

package vmm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ejpir/gantry/internal/vmm/boot"
	"github.com/ejpir/gantry/internal/workerproto"
	"golang.org/x/sys/windows"
)

const (
	whpxBrokerControlSlot       = 3
	whpxBrokerRAMSlot           = 4
	whpxBrokerReadSlot          = 5
	whpxBrokerWriteSlot         = 6
	whpxBrokerMailboxSlot       = 7
	whpxBrokerRequestEventSlot  = 8
	whpxBrokerFirstReplyEvtSlot = 9
)

// WHPXBrokerMain runs the narrow full-token process that owns the process-local
// WHPX partition. It receives no disk, share, network, or console handles.
func WHPXBrokerMain() int {
	control, err := workerproto.InheritedConn(whpxBrokerControlSlot, "WHPX broker control")
	if err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	defer func() { _ = control.Close() }()
	ram, err := workerproto.InheritedFile(whpxBrokerRAMSlot, "WHPX shared RAM")
	if err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	defer func() { _ = ram.Close() }()
	peerRead, err := workerproto.InheritedFile(whpxBrokerReadSlot, "WHPX peer read pipe")
	if err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	peerWrite, err := workerproto.InheritedFile(whpxBrokerWriteSlot, "WHPX peer write pipe")
	if err != nil {
		_ = peerRead.Close()
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	peer := workerproto.NewPipeConn(peerRead, peerWrite)
	defer func() { _ = peer.Close() }()

	var config WHPXBrokerConfig
	if _, err := workerproto.ServeHandshake(control, workerproto.RoleWHPX, &config); err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	if err := validateWHPXBrokerConfig(config); err != nil {
		_ = workerproto.WriteMessage(control, WHPXBrokerBootAck{Error: err.Error()})
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	mailbox, err := workerproto.InheritedFile(whpxBrokerMailboxSlot, "WHPX mailbox section")
	if err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	defer func() { _ = mailbox.Close() }()
	requestEvent, err := workerproto.InheritedFile(whpxBrokerRequestEventSlot, "WHPX request event")
	if err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}
	defer func() { _ = requestEvent.Close() }()
	replyEvents := make([]*os.File, 0, config.VCPUs)
	defer func() {
		for _, event := range replyEvents {
			_ = event.Close()
		}
	}()
	for vp := 0; vp < config.VCPUs; vp++ {
		event, eventErr := workerproto.InheritedFile(uintptr(whpxBrokerFirstReplyEvtSlot+vp), fmt.Sprintf("WHPX reply event %d", vp))
		if eventErr != nil {
			fmt.Fprintln(os.Stderr, "_whpx-worker:", eventErr)
			return 2
		}
		replyEvents = append(replyEvents, event)
	}

	frequency, _ := whpxProcessorClockFrequency()
	if err := workerproto.WriteMessage(control, WHPXBrokerBootAck{
		OK: true, ProcessorClockFrequency: frequency,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 2
	}

	// Control-channel loss revokes the broker even if its direct peer remains
	// open because of a target-side failure.
	go func() {
		var ignored any
		_ = workerproto.ReadMessage(control, &ignored)
		_ = peer.Close()
	}()
	if err := serveWHPXBroker(peer, ram, mailbox, requestEvent, replyEvents, config); err != nil {
		fmt.Fprintln(os.Stderr, "_whpx-worker:", err)
		return 1
	}
	return 0
}

func validateWHPXBrokerConfig(config WHPXBrokerConfig) error {
	if err := ValidateResources(config.MemSize, config.VCPUs); err != nil {
		return err
	}
	if len(config.PeerToken) != 64 {
		return fmt.Errorf("invalid WHPX broker peer token")
	}
	return nil
}

type whpxBrokerSession struct {
	conn      net.Conn
	config    WHPXBrokerConfig
	ramBase   uintptr
	partition windows.Handle
	createdVP []bool
	hot       *whpxBrokerRegion
	hotMapped bool

	writeMu  sync.Mutex
	nativeMu sync.RWMutex
	runMu    sync.Mutex
	running  []bool

	mailboxes *whpxMailboxView
	nextID    atomic.Uint64

	stopOnce  sync.Once
	stopCh    chan struct{}
	stopErrMu sync.Mutex
	stopErr   error
}

func serveWHPXBroker(conn net.Conn, ram, mailbox, requestEvent *os.File, replyEvents []*os.File, config WHPXBrokerConfig) (resultErr error) {
	const fileMapReadWrite = 0x0002 | 0x0004
	base, err := windows.MapViewOfFile(windows.Handle(ram.Fd()), fileMapReadWrite, 0, 0, uintptr(config.MemSize))
	if err != nil {
		return fmt.Errorf("map shared guest RAM: %w", err)
	}
	defer func() {
		if unmapErr := windows.UnmapViewOfFile(base); unmapErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("unmap shared guest RAM: %w", unmapErr))
		}
	}()

	var first whpxBrokerEnvelope
	if err := workerproto.ReadMessage(conn, &first); err != nil {
		return fmt.Errorf("read WHPX setup: %w", err)
	}
	if first.Type != "setup" || first.Token != config.PeerToken || first.Setup == nil {
		return fmt.Errorf("invalid WHPX peer setup")
	}
	mailboxes, err := mapWHPXMailboxView(mailbox, requestEvent, replyEvents, config.VCPUs)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, mailboxes.close()) }()
	s := &whpxBrokerSession{
		conn: conn, config: config, ramBase: base, mailboxes: mailboxes,
		createdVP: make([]bool, config.VCPUs), running: make([]bool, config.VCPUs),
		stopCh: make(chan struct{}),
	}
	if err := s.setup(*first.Setup); err != nil {
		_ = s.write(whpxBrokerEnvelope{Type: "setup-error", Error: err.Error()})
		_ = s.closeNative()
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, s.closeNative()) }()
	if err := s.write(whpxBrokerEnvelope{Type: "setup-ok"}); err != nil {
		return err
	}

	go s.readPeer()
	var workers sync.WaitGroup
	for vp := 0; vp < config.VCPUs; vp++ {
		workers.Add(1)
		go func(vcpu uint32) {
			defer workers.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := s.runVP(vcpu); err != nil {
				s.stop(fmt.Errorf("vCPU %d: %w", vcpu, err))
			}
		}(uint32(vp))
	}
	<-s.stopCh
	s.cancelRunning()
	workers.Wait()
	err = s.err()
	message := whpxBrokerEnvelope{Type: "done"}
	if err != nil {
		message.Error = err.Error()
	}
	_ = s.write(message)
	return err
}

func (s *whpxBrokerSession) setup(setup whpxBrokerSetup) error {
	if setup.VCPUs != s.config.VCPUs || setup.Entry >= s.config.MemSize || len(setup.Initial) == 0 || len(setup.Initial) > 2 {
		return fmt.Errorf("invalid WHPX partition setup")
	}
	validateRegion := func(region whpxBrokerRegion) error {
		if region.Size == 0 || region.HostOffset > s.config.MemSize || region.Size > s.config.MemSize-region.HostOffset ||
			region.GuestBase+region.Size < region.GuestBase {
			return fmt.Errorf("invalid WHPX RAM region %#x+%#x", region.GuestBase, region.Size)
		}
		return nil
	}
	for _, region := range setup.Initial {
		if err := validateRegion(region); err != nil {
			return err
		}
	}
	if setup.Hot != nil {
		if err := validateRegion(*setup.Hot); err != nil {
			return err
		}
		hot := *setup.Hot
		s.hot = &hot
	}

	var partition windows.Handle
	if err := whvCall("WHvCreatePartition", procCreatePartition, uintptr(unsafe.Pointer(&partition))); err != nil {
		return err
	}
	s.partition = partition
	prop := u64Value(uint64(setup.VCPUs))
	if err := whvCall("WHvSetPartitionProperty(ProcessorCount)", procSetPartitionProp,
		uintptr(partition), whvPropProcessorCount, uintptr(unsafe.Pointer(&prop)), 16); err != nil {
		return err
	}
	apicMode := u64Value(1)
	if err := whvCall("WHvSetPartitionProperty(LocalApicEmulationMode)", procSetPartitionProp,
		uintptr(partition), whvPropLocalApicEmulationMode, uintptr(unsafe.Pointer(&apicMode)), 16); err != nil {
		return err
	}
	if err := whvCall("WHvSetupPartition", procSetupPartition, uintptr(partition)); err != nil {
		return err
	}
	for _, region := range setup.Initial {
		if err := s.mapRegion(region); err != nil {
			return err
		}
	}
	for vp := 0; vp < setup.VCPUs; vp++ {
		if err := whvCall("WHvCreateVirtualProcessor", procCreateVP, uintptr(partition), uintptr(vp), 0); err != nil {
			return err
		}
		s.createdVP[vp] = true
	}
	code := segValue(0, 0xffffffff, 0x10, 0xa09b)
	data := segValue(0, 0xffffffff, 0x18, 0x8093)
	return s.setRegs(0, map[uint32]whvRegValue{
		whvRegRip: u64Value(setup.Entry), whvRegRsi: bootZeroPageValue(), whvRegRsp: bootStackValue(),
		whvRegRflags: u64Value(0x2), whvRegCs: code, whvRegDs: data, whvRegEs: data,
		whvRegSs: data, whvRegFs: data, whvRegGs: data,
		whvRegCr0: u64Value(0x80010033), whvRegCr3: bootPML4Value(), whvRegCr4: u64Value(0x20),
		whvRegEfer: u64Value(0x500), whvRegGdtr: bootGDTValue(), whvRegIdtr: tableValue(0, 0xffff),
	})
}

func (s *whpxBrokerSession) mapRegion(region whpxBrokerRegion) error {
	return whvCall("WHvMapGpaRange", procMapGpaRange,
		uintptr(s.partition), s.ramBase+uintptr(region.HostOffset), uintptr(region.GuestBase),
		uintptr(region.Size), whvMapRead|whvMapWrite|whvMapExecute)
}

func (s *whpxBrokerSession) readPeer() {
	for {
		var message whpxBrokerEnvelope
		if err := workerproto.ReadMessage(s.conn, &message); err != nil {
			s.stop(fmt.Errorf("WHPX peer: %w", err))
			return
		}
		switch message.Type {
		case "interrupt":
			if message.Interrupt == nil || message.Interrupt.Destination >= uint32(s.config.VCPUs) || message.Interrupt.Vector > 255 {
				s.stop(fmt.Errorf("invalid WHPX interrupt"))
				return
			}
			if err := s.injectInterrupt(*message.Interrupt); err != nil {
				s.stop(err)
				return
			}
		case "map-hot":
			err := s.mapHot()
			reply := whpxBrokerEnvelope{Type: "command-reply", ID: message.ID}
			if err != nil {
				reply.Error = err.Error()
			}
			if writeErr := s.write(reply); writeErr != nil {
				s.stop(writeErr)
				return
			}
		case "close":
			s.stop(nil)
			return
		default:
			s.stop(fmt.Errorf("unknown WHPX peer message %q", message.Type))
			return
		}
	}
}

func (s *whpxBrokerSession) runVP(vp uint32) error {
	context := make([]byte, whvExitContextSize)
	allGPRNames := []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	for {
		select {
		case <-s.stopCh:
			return nil
		default:
		}
		s.runMu.Lock()
		s.running[vp] = true
		s.runMu.Unlock()
		err := whvCall("WHvRunVirtualProcessor", procRunVP, uintptr(s.partition), uintptr(vp),
			uintptr(unsafe.Pointer(&context[0])), uintptr(len(context)))
		s.runMu.Lock()
		s.running[vp] = false
		s.runMu.Unlock()
		if err != nil {
			select {
			case <-s.stopCh:
				return nil
			default:
				return err
			}
		}
		reason := binary.LittleEndian.Uint32(context)
		switch reason {
		case whvExitMemoryAccess, whvExitIoPort:
			exit := whpxBrokerExit{ID: s.nextID.Add(1), VCPU: vp, Context: append([]byte(nil), context...)}
			if reason == whvExitMemoryAccess {
				values, err := s.getRegs(vp, allGPRNames)
				if err != nil {
					return err
				}
				exit.GPRs = make([]uint64, len(values))
				for index := range values {
					exit.GPRs[index] = binary.LittleEndian.Uint64(values[index][:8])
				}
			}
			reply, err := s.requestExit(exit)
			if err != nil {
				return err
			}
			if reply.Error != "" {
				return fmt.Errorf("device worker: %s", reply.Error)
			}
			if reply.Stop {
				s.stop(nil)
				return nil
			}
			if len(reply.RegisterNames) == 0 || len(reply.RegisterNames) != len(reply.RegisterValues) || len(reply.RegisterNames) > 2 {
				return fmt.Errorf("invalid register reply for exit %d", exit.ID)
			}
			for _, name := range reply.RegisterNames {
				if name > whvRegRflags {
					return fmt.Errorf("disallowed register %#x in exit reply", name)
				}
			}
			if err := s.writeGPRs(vp, reply.RegisterNames, reply.RegisterValues); err != nil {
				return err
			}
		case whvExitHalt, whvExitInterruptWin, whvExitMsrAccess, whvExitCpuid:
		case whvExitCanceled:
			select {
			case <-s.stopCh:
				return nil
			default:
			}
		case whvExitUnrecoverable:
			return fmt.Errorf("unrecoverable guest exception at RIP %#x", binary.LittleEndian.Uint64(context[32:]))
		case whvExitInvalidVpReg:
			return fmt.Errorf("invalid virtual processor register")
		}
	}
}

func (s *whpxBrokerSession) requestExit(exit whpxBrokerExit) (whpxBrokerReply, error) {
	if err := s.mailboxes.sendExit(exit); err != nil {
		return whpxBrokerReply{}, err
	}
	reply, err := s.mailboxes.waitReply(exit.VCPU, exit.ID)
	if err != nil {
		select {
		case <-s.stopCh:
			return whpxBrokerReply{}, s.err()
		default:
		}
		return whpxBrokerReply{}, err
	}
	return reply, nil
}

func (s *whpxBrokerSession) mapHot() error {
	s.nativeMu.Lock()
	defer s.nativeMu.Unlock()
	if s.partition == 0 {
		return fmt.Errorf("WHPX partition is closed")
	}
	if s.hot == nil || s.hotMapped {
		return fmt.Errorf("WHPX hot-memory mapping unavailable")
	}
	if err := s.mapRegion(*s.hot); err != nil {
		return err
	}
	s.hotMapped = true
	return nil
}

func (s *whpxBrokerSession) injectInterrupt(interrupt whpxBrokerInterrupt) error {
	s.nativeMu.RLock()
	defer s.nativeMu.RUnlock()
	if s.partition == 0 {
		return fmt.Errorf("WHPX partition is closed")
	}
	var ctrl [16]byte
	if interrupt.Level {
		binary.LittleEndian.PutUint64(ctrl[:8], 1<<12)
	}
	binary.LittleEndian.PutUint32(ctrl[8:12], interrupt.Destination)
	binary.LittleEndian.PutUint32(ctrl[12:16], interrupt.Vector)
	return whvCall("WHvRequestInterrupt", procRequestInterrupt,
		uintptr(s.partition), uintptr(unsafe.Pointer(&ctrl[0])), uintptr(len(ctrl)))
}

func (s *whpxBrokerSession) getRegs(vp uint32, names []uint32) ([]whvRegValue, error) {
	values := make([]whvRegValue, len(names))
	err := whvCall("WHvGetVirtualProcessorRegisters", procGetVPRegs,
		uintptr(s.partition), uintptr(vp), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)),
		uintptr(unsafe.Pointer(&values[0])))
	return values, err
}

func (s *whpxBrokerSession) setRegs(vp uint32, regs map[uint32]whvRegValue) error {
	names := make([]uint32, 0, len(regs))
	values := make([]whvRegValue, 0, len(regs))
	for name, value := range regs {
		names = append(names, name)
		values = append(values, value)
	}
	return whvCall("WHvSetVirtualProcessorRegisters", procSetVPRegs,
		uintptr(s.partition), uintptr(vp), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)),
		uintptr(unsafe.Pointer(&values[0])))
}

func (s *whpxBrokerSession) writeGPRs(vp uint32, names []uint32, raw []uint64) error {
	values := make([]whvRegValue, len(raw))
	for index, value := range raw {
		values[index] = u64Value(value)
	}
	return whvCall("WHvSetVirtualProcessorRegisters", procSetVPRegs,
		uintptr(s.partition), uintptr(vp), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)),
		uintptr(unsafe.Pointer(&values[0])))
}

func (s *whpxBrokerSession) cancelRunning() {
	s.runMu.Lock()
	running := append([]bool(nil), s.running...)
	s.runMu.Unlock()
	for vp, active := range running {
		if active {
			_ = whvCall("WHvCancelRunVirtualProcessor", procCancelRunVP, uintptr(s.partition), uintptr(vp), 0)
		}
	}
}

func (s *whpxBrokerSession) closeNative() error {
	s.nativeMu.Lock()
	defer s.nativeMu.Unlock()
	var errs []error
	for vp := len(s.createdVP) - 1; vp >= 0; vp-- {
		if s.createdVP[vp] {
			errs = append(errs, whvCall("WHvDeleteVirtualProcessor", procDeleteVP, uintptr(s.partition), uintptr(vp)))
			s.createdVP[vp] = false
		}
	}
	if s.partition != 0 {
		errs = append(errs, whvCall("WHvDeletePartition", procDeletePartition, uintptr(s.partition)))
		s.partition = 0
	}
	return errors.Join(errs...)
}

func (s *whpxBrokerSession) write(message whpxBrokerEnvelope) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return workerproto.WriteMessage(s.conn, message)
}

func (s *whpxBrokerSession) stop(err error) {
	s.stopOnce.Do(func() {
		s.stopErrMu.Lock()
		s.stopErr = err
		s.stopErrMu.Unlock()
		close(s.stopCh)
		if s.mailboxes != nil {
			s.mailboxes.signalReplies()
		}
		s.cancelRunning()
	})
}

func (s *whpxBrokerSession) err() error {
	s.stopErrMu.Lock()
	defer s.stopErrMu.Unlock()
	return s.stopErr
}

// Keep the broker independent of Machine while sharing the exact boot ABI.
func bootZeroPageValue() whvRegValue { return u64Value(boot.ZeroPage) }
func bootStackValue() whvRegValue    { return u64Value(boot.StackTop - 0x10) }
func bootPML4Value() whvRegValue     { return u64Value(boot.PML4) }
func bootGDTValue() whvRegValue      { return tableValue(boot.GDT, 4*8-1) }
