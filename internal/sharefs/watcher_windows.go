//go:build windows

package sharefs

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsShareWatcher struct {
	handle windows.Handle
	emit   func(shareWatchEvent)
	closed atomic.Bool
	done   chan struct{}
}

func newPlatformShareWatcher(export *Export, emit func(shareWatchEvent)) (shareWatcher, error) {
	if export == nil || export.watchRootHandle == 0 {
		return nil, fmt.Errorf("share root handle is unavailable")
	}
	handle, err := duplicateWinHandle(windows.Handle(export.watchRootHandle))
	if err != nil {
		return nil, err
	}
	watcher := &windowsShareWatcher{handle: handle, emit: emit, done: make(chan struct{})}
	go watcher.run()
	return watcher, nil
}

func (w *windowsShareWatcher) WatchDirectory(string) error { return nil }
func (w *windowsShareWatcher) ForgetDirectory(string)      {}
func (w *windowsShareWatcher) Reset() error                { return nil }

func (w *windowsShareWatcher) Close() error {
	if w == nil || !w.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = windows.CancelIoEx(w.handle, nil)
	err := windows.CloseHandle(w.handle)
	<-w.done
	return err
}

func (w *windowsShareWatcher) run() {
	defer close(w.done)
	buffer := make([]byte, 64<<10)
	mask := uint32(windows.FILE_NOTIFY_CHANGE_FILE_NAME |
		windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_ATTRIBUTES |
		windows.FILE_NOTIFY_CHANGE_SIZE |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_CREATION |
		windows.FILE_NOTIFY_CHANGE_SECURITY)
	for !w.closed.Load() {
		var returned uint32
		err := windows.ReadDirectoryChanges(w.handle, &buffer[0], uint32(len(buffer)), true,
			mask, &returned, nil, 0)
		if err != nil {
			if w.closed.Load() || errors.Is(err, windows.ERROR_OPERATION_ABORTED) || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
				return
			}
			w.emit(shareWatchEvent{loss: fmt.Errorf("ReadDirectoryChangesW: %w", err)})
			return
		}
		if returned == 0 || returned > uint32(len(buffer)) {
			w.emit(shareWatchEvent{loss: fmt.Errorf("ReadDirectoryChangesW overflow")})
			return
		}
		w.process(buffer[:returned])
	}
}

func (w *windowsShareWatcher) process(buffer []byte) {
	const headerSize = int(unsafe.Offsetof(windows.FileNotifyInformation{}.FileName))
	for len(buffer) >= headerSize {
		info := (*windows.FileNotifyInformation)(unsafe.Pointer(&buffer[0]))
		nameBytes := int(info.FileNameLength)
		if nameBytes < 0 || nameBytes%2 != 0 || headerSize+nameBytes > len(buffer) {
			w.emit(shareWatchEvent{loss: fmt.Errorf("malformed ReadDirectoryChangesW record")})
			return
		}
		name := windows.UTF16ToString(unsafe.Slice(&info.FileName, nameBytes/2))
		name = strings.ReplaceAll(name, `\`, "/")
		rename := info.Action == windows.FILE_ACTION_RENAMED_OLD_NAME ||
			info.Action == windows.FILE_ACTION_RENAMED_NEW_NAME
		w.emit(shareWatchEvent{
			rel: name, rename: rename,
			invalidateDirs: rename || info.Action == windows.FILE_ACTION_REMOVED,
		})
		if info.NextEntryOffset == 0 {
			return
		}
		next := int(info.NextEntryOffset)
		if next < headerSize || next > len(buffer) {
			w.emit(shareWatchEvent{loss: fmt.Errorf("invalid ReadDirectoryChangesW offset")})
			return
		}
		buffer = buffer[next:]
	}
}
