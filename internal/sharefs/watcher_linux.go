//go:build linux

package sharefs

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const linuxShareWatchMask = unix.IN_ATTRIB |
	unix.IN_CLOSE_WRITE |
	unix.IN_CREATE |
	unix.IN_DELETE |
	unix.IN_DELETE_SELF |
	unix.IN_MODIFY |
	unix.IN_MOVE_SELF |
	unix.IN_MOVED_FROM |
	unix.IN_MOVED_TO |
	unix.IN_EXCL_UNLINK |
	unix.IN_ONLYDIR

type linuxShareWatcher struct {
	mu     sync.Mutex
	fd     int
	wakeFD int
	rootFD int
	closed bool
	byPath map[string]int
	byWD   map[int]string
	emit   func(shareWatchEvent)
	done   chan struct{}
}

func newPlatformShareWatcher(export *Export, emit func(shareWatchEvent)) (shareWatcher, error) {
	if export == nil || export.watchRootFD < 0 {
		return nil, fmt.Errorf("share root descriptor is unavailable")
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	wakeFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	watcher := &linuxShareWatcher{
		fd: fd, wakeFD: wakeFD, rootFD: export.watchRootFD,
		byPath: make(map[string]int), byWD: make(map[int]string),
		emit: emit, done: make(chan struct{}),
	}
	if err := watcher.watchDirectoryLocked(""); err != nil {
		_ = unix.Close(fd)
		_ = unix.Close(wakeFD)
		return nil, err
	}
	go watcher.run()
	return watcher, nil
}

func (w *linuxShareWatcher) WatchDirectory(rel string) error {
	rel, ok := cleanCoherenceRel(rel)
	if !ok {
		return syscall.EINVAL
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return syscall.EBADF
	}
	return w.watchDirectoryLocked(rel)
}

func (w *linuxShareWatcher) watchDirectoryLocked(rel string) error {
	if _, exists := w.byPath[rel]; exists {
		return nil
	}
	if len(w.byPath) >= maxLiveNodes {
		return fmt.Errorf("directory watch budget %d exceeded", maxLiveNodes)
	}
	dirFD, err := openWatchedDirAt(w.rootFD, rel)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dirFD) }()
	wd, err := unix.InotifyAddWatch(w.fd, fmt.Sprintf("/proc/self/fd/%d", dirFD), linuxShareWatchMask)
	if err != nil {
		return err
	}
	if previous, exists := w.byWD[wd]; exists && previous != rel {
		delete(w.byPath, previous)
	}
	w.byPath[rel] = wd
	w.byWD[wd] = rel
	return nil
}

func openWatchedDirAt(rootFD int, rel string) (int, error) {
	current, err := unix.FcntlInt(uintptr(rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if rel == "" {
		return current, nil
	}
	for _, component := range strings.Split(rel, "/") {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(current)
			return -1, syscall.EINVAL
		}
		next, openErr := unix.Openat(current, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
	}
	return current, nil
}

func (w *linuxShareWatcher) ForgetDirectory(rel string) {
	rel, ok := cleanCoherenceRel(rel)
	if !ok || rel == "" {
		return
	}
	w.mu.Lock()
	wd, exists := w.byPath[rel]
	if exists {
		delete(w.byPath, rel)
		delete(w.byWD, wd)
		_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
	}
	w.mu.Unlock()
}

func (w *linuxShareWatcher) Reset() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return syscall.EBADF
	}
	for rel, wd := range w.byPath {
		delete(w.byPath, rel)
		delete(w.byWD, wd)
		_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
	}
	return w.watchDirectoryLocked("")
}

func (w *linuxShareWatcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		<-w.done
		return nil
	}
	w.closed = true
	fd, wakeFD := w.fd, w.wakeFD
	w.mu.Unlock()
	var wake [8]byte
	wake[0] = 1
	_, _ = unix.Write(wakeFD, wake[:])
	<-w.done
	return errors.Join(unix.Close(fd), unix.Close(wakeFD))
}

func (w *linuxShareWatcher) run() {
	defer close(w.done)
	buffer := make([]byte, 64<<10)
	for {
		w.mu.Lock()
		closed, fd := w.closed, w.fd
		w.mu.Unlock()
		if closed {
			return
		}
		poll := []unix.PollFd{
			{Fd: int32(fd), Events: unix.POLLIN},
			{Fd: int32(w.wakeFD), Events: unix.POLLIN},
		}
		_, err := unix.Poll(poll, -1)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			w.reportLoss(fmt.Errorf("poll inotify: %w", err))
			return
		}
		if poll[1].Revents&unix.POLLIN != 0 {
			return
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := unix.Read(fd, buffer)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			w.reportLoss(fmt.Errorf("read inotify: %w", err))
			return
		}
		w.process(buffer[:n])
	}
}

// linuxWatchRecord is one parsed inotify event. Records are parsed per read
// buffer so that an IN_MOVED_FROM can be paired with the IN_MOVED_TO that
// shares its cookie: one host rename must surface as a single watch event,
// otherwise the second half would sweep path mappings that guests already
// re-established after the first half was handled.
type linuxWatchRecord struct {
	mask   uint32
	cookie uint32
	wd     int32
	name   string
}

func (w *linuxShareWatcher) process(buffer []byte) {
	const headerSize = int(unsafe.Sizeof(unix.InotifyEvent{}))
	var records []linuxWatchRecord
	for len(buffer) >= headerSize {
		event := (*unix.InotifyEvent)(unsafe.Pointer(&buffer[0]))
		recordSize := headerSize + int(event.Len)
		if recordSize < headerSize || recordSize > len(buffer) {
			w.reportLoss(fmt.Errorf("malformed inotify record"))
			return
		}
		if event.Mask&unix.IN_Q_OVERFLOW != 0 {
			w.reportLoss(fmt.Errorf("inotify queue overflow"))
			return
		}
		nameBytes := buffer[headerSize:recordSize]
		if nul := strings.IndexByte(string(nameBytes), 0); nul >= 0 {
			nameBytes = nameBytes[:nul]
		}
		records = append(records, linuxWatchRecord{
			mask: event.Mask, cookie: event.Cookie, wd: event.Wd, name: string(nameBytes),
		})
		buffer = buffer[recordSize:]
	}
	if len(buffer) != 0 {
		w.reportLoss(fmt.Errorf("trailing inotify bytes"))
		return
	}
	consumed := make([]bool, len(records))
	for i, rec := range records {
		if consumed[i] {
			continue
		}
		event, ok := w.classifyRecord(rec)
		if !ok {
			continue
		}
		if rec.mask&unix.IN_MOVED_FROM != 0 && rec.cookie != 0 {
			for j := i + 1; j < len(records); j++ {
				pair := records[j]
				if consumed[j] || pair.mask&unix.IN_MOVED_TO == 0 || pair.cookie != rec.cookie {
					continue
				}
				consumed[j] = true
				if target, targetOK := w.classifyRecord(pair); targetOK && target.loss == nil {
					event.relTo = target.rel
					event.invalidateDirs = event.invalidateDirs || target.invalidateDirs
				}
				break
			}
		}
		if event.loss != nil {
			w.reportLoss(event.loss)
			return
		}
		w.emit(event)
	}
}

// classifyRecord resolves a record to a watch event, applying watch-lifetime
// bookkeeping for watches the kernel dropped. ok is false for records that
// must not be emitted (unknown watch or IN_IGNORED teardown).
func (w *linuxShareWatcher) classifyRecord(rec linuxWatchRecord) (shareWatchEvent, bool) {
	w.mu.Lock()
	rel, known := w.byWD[int(rec.wd)]
	if rec.mask&(unix.IN_IGNORED|unix.IN_DELETE_SELF) != 0 && known && rel != "" {
		delete(w.byWD, int(rec.wd))
		delete(w.byPath, rel)
	}
	w.mu.Unlock()
	if !known || rec.mask&unix.IN_IGNORED != 0 {
		return shareWatchEvent{}, false
	}
	full := rel
	if rec.name != "" {
		full = path.Join(rel, rec.name)
	}
	event := shareWatchEvent{
		rel:    full,
		rename: rec.mask&(unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_MOVE_SELF) != 0,
		invalidateDirs: rec.mask&unix.IN_ISDIR != 0 &&
			rec.mask&(unix.IN_DELETE|unix.IN_DELETE_SELF|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_MOVE_SELF) != 0,
	}
	loss := rec.mask&unix.IN_UNMOUNT != 0 || rec.mask&unix.IN_DELETE_SELF != 0 && rel == ""
	if loss {
		event.loss = fmt.Errorf("export root was removed or unmounted")
	}
	return event, true
}

func (w *linuxShareWatcher) reportLoss(err error) {
	if w.emit != nil {
		w.emit(shareWatchEvent{loss: err})
	}
}
