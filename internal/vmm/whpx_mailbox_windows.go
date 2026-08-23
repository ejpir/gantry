//go:build windows

package vmm

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	whpxMailboxStride       = 512
	whpxMailboxMagic        = 0x58425047 // "GPBX", little endian
	whpxMailboxStateIdle    = 0
	whpxMailboxStateRequest = 1
	whpxMailboxStateClaimed = 2
	whpxMailboxStateReply   = 3

	whpxMailboxStateOffset      = 4
	whpxMailboxSequenceOffset   = 8
	whpxMailboxVCPUOffset       = 16
	whpxMailboxContextLenOffset = 20
	whpxMailboxGPRCountOffset   = 24
	whpxMailboxContextOffset    = 32
	whpxMailboxGPROffset        = 256
	whpxMailboxReplySeqOffset   = 384
	whpxMailboxReplyFlagsOffset = 392
	whpxMailboxReplyCountOffset = 396
	whpxMailboxReplyNamesOffset = 400
	whpxMailboxReplyValuesOff   = 408
	whpxMailboxErrorLenOffset   = 424
	whpxMailboxErrorOffset      = 428
	whpxMailboxErrorMax         = whpxMailboxStride - whpxMailboxErrorOffset

	whpxMailboxReplyStop = 1

	// A bounded spin bridges the short cross-process scheduling window during
	// exit-heavy bursts. Both paths still consume the kernel event, preserving
	// lost-wakeup protection without keeping a core busy while the guest runs.
	whpxMailboxSpinCount = 20000
)

// WHPXMailboxFiles is the anonymous shared-memory/event capability set used
// only for validated vCPU-exit requests. Request notification is aggregated;
// each vCPU has a distinct reply event so one run loop cannot consume another
// vCPU's wakeup.
type WHPXMailboxFiles struct {
	Mapping      *os.File
	RequestEvent *os.File
	ReplyEvents  []*os.File
}

// NewWHPXMailboxFiles creates unnamed kernel objects. Possession can only be
// transferred through the explicit worker handle allowlists.
func NewWHPXMailboxFiles(vcpus int) (WHPXMailboxFiles, error) {
	var result WHPXMailboxFiles
	if vcpus < 1 || vcpus > MaxVCPUs {
		return result, fmt.Errorf("WHPX mailboxes: invalid vCPU count %d", vcpus)
	}
	size := uint64(vcpus * whpxMailboxStride)
	mapping, err := windows.CreateFileMapping(
		windows.InvalidHandle, nil, windows.PAGE_READWRITE,
		uint32(size>>32), uint32(size), nil,
	)
	if err != nil {
		return result, fmt.Errorf("create WHPX mailbox section: %w", err)
	}
	result.Mapping = os.NewFile(uintptr(mapping), "gantry-whpx-mailboxes")
	if result.Mapping == nil {
		_ = windows.CloseHandle(mapping)
		return WHPXMailboxFiles{}, fmt.Errorf("wrap WHPX mailbox section")
	}
	newEvent := func(name string) (*os.File, error) {
		handle, eventErr := windows.CreateEvent(nil, 0, 0, nil)
		if eventErr != nil {
			return nil, eventErr
		}
		file := os.NewFile(uintptr(handle), name)
		if file == nil {
			_ = windows.CloseHandle(handle)
			return nil, fmt.Errorf("wrap event handle")
		}
		return file, nil
	}
	result.RequestEvent, err = newEvent("gantry-whpx-request")
	if err != nil {
		_ = result.Close()
		return WHPXMailboxFiles{}, fmt.Errorf("create WHPX request event: %w", err)
	}
	for vp := 0; vp < vcpus; vp++ {
		event, eventErr := newEvent(fmt.Sprintf("gantry-whpx-reply-%d", vp))
		if eventErr != nil {
			_ = result.Close()
			return WHPXMailboxFiles{}, fmt.Errorf("create WHPX reply event %d: %w", vp, eventErr)
		}
		result.ReplyEvents = append(result.ReplyEvents, event)
	}
	return result, nil
}

func (files *WHPXMailboxFiles) Close() error {
	if files == nil {
		return nil
	}
	var first error
	closeFile := func(file **os.File) {
		if *file != nil {
			if err := (*file).Close(); err != nil && first == nil {
				first = err
			}
			*file = nil
		}
	}
	closeFile(&files.Mapping)
	closeFile(&files.RequestEvent)
	for index := range files.ReplyEvents {
		closeFile(&files.ReplyEvents[index])
	}
	files.ReplyEvents = nil
	return first
}

type whpxMailboxView struct {
	base         uintptr
	size         uintptr
	vcpus        int
	requestEvent windows.Handle
	replyEvents  []windows.Handle
}

func mapWHPXMailboxView(mapping, requestEvent *os.File, replyEvents []*os.File, vcpus int) (*whpxMailboxView, error) {
	if mapping == nil || requestEvent == nil || len(replyEvents) != vcpus || vcpus < 1 {
		return nil, fmt.Errorf("invalid WHPX mailbox handle table")
	}
	size := uintptr(vcpus * whpxMailboxStride)
	const fileMapReadWrite = 0x0002 | 0x0004
	base, err := windows.MapViewOfFile(windows.Handle(mapping.Fd()), fileMapReadWrite, 0, 0, size)
	if err != nil {
		return nil, fmt.Errorf("map WHPX mailboxes: %w", err)
	}
	view := &whpxMailboxView{
		base: base, size: size, vcpus: vcpus, requestEvent: windows.Handle(requestEvent.Fd()),
		replyEvents: make([]windows.Handle, vcpus),
	}
	for index, event := range replyEvents {
		if event == nil {
			_ = view.close()
			return nil, fmt.Errorf("nil WHPX reply event %d", index)
		}
		view.replyEvents[index] = windows.Handle(event.Fd())
	}
	return view, nil
}

func (view *whpxMailboxView) close() error {
	if view == nil || view.base == 0 {
		return nil
	}
	err := windows.UnmapViewOfFile(view.base)
	view.base = 0
	view.size = 0
	return err
}

func (view *whpxMailboxView) slot(vp uint32) ([]byte, error) {
	if view == nil || view.base == 0 || vp >= uint32(view.vcpus) {
		return nil, fmt.Errorf("invalid WHPX mailbox vCPU %d", vp)
	}
	base := view.base + uintptr(vp)*whpxMailboxStride
	// MapViewOfFile returns the mapped address as uintptr; converting that
	// validated in-range address is the Windows API boundary.
	return unsafe.Slice((*byte)(unsafe.Pointer(base)), whpxMailboxStride), nil //nolint:govet
}

func mailboxState(slot []byte) *uint32 {
	return (*uint32)(unsafe.Pointer(&slot[whpxMailboxStateOffset]))
}

func (view *whpxMailboxView) sendExit(exit whpxBrokerExit) error {
	slot, err := view.slot(exit.VCPU)
	if err != nil {
		return err
	}
	if exit.ID == 0 || len(exit.Context) != whvExitContextSize || (len(exit.GPRs) != 0 && len(exit.GPRs) != 16) {
		return fmt.Errorf("invalid WHPX mailbox exit")
	}
	if atomic.LoadUint32(mailboxState(slot)) != whpxMailboxStateIdle {
		return fmt.Errorf("WHPX mailbox %d is not idle", exit.VCPU)
	}
	binary.LittleEndian.PutUint32(slot[0:], whpxMailboxMagic)
	binary.LittleEndian.PutUint64(slot[whpxMailboxSequenceOffset:], exit.ID)
	binary.LittleEndian.PutUint32(slot[whpxMailboxVCPUOffset:], exit.VCPU)
	binary.LittleEndian.PutUint32(slot[whpxMailboxContextLenOffset:], uint32(len(exit.Context)))
	binary.LittleEndian.PutUint32(slot[whpxMailboxGPRCountOffset:], uint32(len(exit.GPRs)))
	copy(slot[whpxMailboxContextOffset:whpxMailboxContextOffset+whvExitContextSize], exit.Context)
	for index, value := range exit.GPRs {
		binary.LittleEndian.PutUint64(slot[whpxMailboxGPROffset+8*index:], value)
	}
	binary.LittleEndian.PutUint64(slot[whpxMailboxReplySeqOffset:], 0)
	binary.LittleEndian.PutUint32(slot[whpxMailboxReplyFlagsOffset:], 0)
	binary.LittleEndian.PutUint32(slot[whpxMailboxReplyCountOffset:], 0)
	binary.LittleEndian.PutUint32(slot[whpxMailboxErrorLenOffset:], 0)
	atomic.StoreUint32(mailboxState(slot), whpxMailboxStateRequest)
	if err := windows.SetEvent(view.requestEvent); err != nil {
		atomic.StoreUint32(mailboxState(slot), whpxMailboxStateIdle)
		return fmt.Errorf("signal WHPX request event: %w", err)
	}
	return nil
}

func (view *whpxMailboxView) waitReply(vp uint32, sequence uint64) (whpxBrokerReply, error) {
	if vp >= uint32(len(view.replyEvents)) {
		return whpxBrokerReply{}, fmt.Errorf("invalid WHPX reply vCPU %d", vp)
	}
	slot, err := view.slot(vp)
	if err != nil {
		return whpxBrokerReply{}, err
	}
	for spin := 0; spin < whpxMailboxSpinCount; spin++ {
		if atomic.LoadUint32(mailboxState(slot)) == whpxMailboxStateReply {
			break
		}
	}
	// Consume the auto-reset event even when the shared state became visible
	// during the spin; otherwise its pending signal could wake the next exit.
	if _, err := windows.WaitForSingleObject(view.replyEvents[vp], windows.INFINITE); err != nil {
		return whpxBrokerReply{}, fmt.Errorf("wait WHPX reply event: %w", err)
	}
	slot, err = view.slot(vp)
	if err != nil {
		return whpxBrokerReply{}, err
	}
	if atomic.LoadUint32(mailboxState(slot)) != whpxMailboxStateReply {
		return whpxBrokerReply{}, fmt.Errorf("WHPX mailbox %d has no reply", vp)
	}
	defer atomic.StoreUint32(mailboxState(slot), whpxMailboxStateIdle)
	if binary.LittleEndian.Uint32(slot[0:]) != whpxMailboxMagic ||
		binary.LittleEndian.Uint64(slot[whpxMailboxReplySeqOffset:]) != sequence {
		return whpxBrokerReply{}, fmt.Errorf("WHPX mailbox %d reply sequence mismatch", vp)
	}
	count := binary.LittleEndian.Uint32(slot[whpxMailboxReplyCountOffset:])
	if count > 2 {
		return whpxBrokerReply{}, fmt.Errorf("WHPX mailbox %d reply register count %d", vp, count)
	}
	reply := whpxBrokerReply{ID: sequence}
	flags := binary.LittleEndian.Uint32(slot[whpxMailboxReplyFlagsOffset:])
	reply.Stop = flags&whpxMailboxReplyStop != 0
	for index := uint32(0); index < count; index++ {
		reply.RegisterNames = append(reply.RegisterNames,
			binary.LittleEndian.Uint32(slot[whpxMailboxReplyNamesOffset+4*int(index):]))
		reply.RegisterValues = append(reply.RegisterValues,
			binary.LittleEndian.Uint64(slot[whpxMailboxReplyValuesOff+8*int(index):]))
	}
	errorLen := binary.LittleEndian.Uint32(slot[whpxMailboxErrorLenOffset:])
	if errorLen > uint32(whpxMailboxErrorMax) {
		return whpxBrokerReply{}, fmt.Errorf("WHPX mailbox %d error length %d", vp, errorLen)
	}
	reply.Error = string(slot[whpxMailboxErrorOffset : whpxMailboxErrorOffset+int(errorLen)])
	return reply, nil
}

func (view *whpxMailboxView) waitRequest() error {
	for spin := 0; spin < whpxMailboxSpinCount; spin++ {
		for vp := 0; vp < view.vcpus; vp++ {
			slot, err := view.slot(uint32(vp))
			if err != nil {
				return err
			}
			if atomic.LoadUint32(mailboxState(slot)) == whpxMailboxStateRequest {
				// Pair the observed state with consumption of the auto-reset
				// event. The producer stores state before signaling it.
				if _, err := windows.WaitForSingleObject(view.requestEvent, windows.INFINITE); err != nil {
					return fmt.Errorf("wait WHPX request event: %w", err)
				}
				return nil
			}
		}
	}
	if _, err := windows.WaitForSingleObject(view.requestEvent, windows.INFINITE); err != nil {
		return fmt.Errorf("wait WHPX request event: %w", err)
	}
	return nil
}

func (view *whpxMailboxView) claimRequests() ([]whpxBrokerExit, error) {
	var exits []whpxBrokerExit
	for vp := 0; vp < view.vcpus; vp++ {
		slot, err := view.slot(uint32(vp))
		if err != nil {
			return nil, err
		}
		if !atomic.CompareAndSwapUint32(mailboxState(slot), whpxMailboxStateRequest, whpxMailboxStateClaimed) {
			continue
		}
		sequence := binary.LittleEndian.Uint64(slot[whpxMailboxSequenceOffset:])
		contextLen := binary.LittleEndian.Uint32(slot[whpxMailboxContextLenOffset:])
		gprCount := binary.LittleEndian.Uint32(slot[whpxMailboxGPRCountOffset:])
		if binary.LittleEndian.Uint32(slot[0:]) != whpxMailboxMagic || sequence == 0 ||
			binary.LittleEndian.Uint32(slot[whpxMailboxVCPUOffset:]) != uint32(vp) ||
			contextLen != whvExitContextSize || (gprCount != 0 && gprCount != 16) {
			_ = view.respond(uint32(vp), whpxBrokerReply{ID: sequence, Stop: true, Error: "invalid WHPX mailbox request"})
			continue
		}
		exit := whpxBrokerExit{ID: sequence, VCPU: uint32(vp), Context: make([]byte, contextLen)}
		copy(exit.Context, slot[whpxMailboxContextOffset:whpxMailboxContextOffset+int(contextLen)])
		for index := uint32(0); index < gprCount; index++ {
			exit.GPRs = append(exit.GPRs, binary.LittleEndian.Uint64(slot[whpxMailboxGPROffset+8*int(index):]))
		}
		exits = append(exits, exit)
	}
	return exits, nil
}

func (view *whpxMailboxView) respond(vp uint32, reply whpxBrokerReply) error {
	slot, err := view.slot(vp)
	if err != nil {
		return err
	}
	if atomic.LoadUint32(mailboxState(slot)) != whpxMailboxStateClaimed {
		return fmt.Errorf("WHPX mailbox %d request was not claimed", vp)
	}
	if len(reply.RegisterNames) != len(reply.RegisterValues) || len(reply.RegisterNames) > 2 {
		return fmt.Errorf("invalid WHPX mailbox register reply")
	}
	binary.LittleEndian.PutUint64(slot[whpxMailboxReplySeqOffset:], reply.ID)
	var flags uint32
	if reply.Stop {
		flags |= whpxMailboxReplyStop
	}
	binary.LittleEndian.PutUint32(slot[whpxMailboxReplyFlagsOffset:], flags)
	binary.LittleEndian.PutUint32(slot[whpxMailboxReplyCountOffset:], uint32(len(reply.RegisterNames)))
	for index := range reply.RegisterNames {
		binary.LittleEndian.PutUint32(slot[whpxMailboxReplyNamesOffset+4*index:], reply.RegisterNames[index])
		binary.LittleEndian.PutUint64(slot[whpxMailboxReplyValuesOff+8*index:], reply.RegisterValues[index])
	}
	errorBytes := []byte(reply.Error)
	if len(errorBytes) > whpxMailboxErrorMax {
		errorBytes = errorBytes[:whpxMailboxErrorMax]
	}
	binary.LittleEndian.PutUint32(slot[whpxMailboxErrorLenOffset:], uint32(len(errorBytes)))
	copy(slot[whpxMailboxErrorOffset:], errorBytes)
	atomic.StoreUint32(mailboxState(slot), whpxMailboxStateReply)
	if err := windows.SetEvent(view.replyEvents[vp]); err != nil {
		return fmt.Errorf("signal WHPX reply event: %w", err)
	}
	return nil
}

func (view *whpxMailboxView) signalRequest() {
	if view != nil && view.requestEvent != 0 {
		_ = windows.SetEvent(view.requestEvent)
	}
}

func (view *whpxMailboxView) signalReplies() {
	if view == nil {
		return
	}
	for _, event := range view.replyEvents {
		_ = windows.SetEvent(event)
	}
}
