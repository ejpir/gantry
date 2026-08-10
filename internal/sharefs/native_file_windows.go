//go:build windows

package sharefs

import (
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// winOpenFile owns one Windows file handle through os.File.
type winOpenFile struct {
	file       *os.File
	appendMode bool
	writable   bool // opened with any write access; Flush/Fsync gate on it
	closeOnce  sync.Once
	closeErr   error
}

func (f *winOpenFile) close() error {
	if f == nil || f.file == nil {
		return nil
	}
	f.closeOnce.Do(func() { f.closeErr = f.file.Close() })
	return f.closeErr
}

func (f *winOpenFile) read(dest []byte, off int64) (int, error) {
	n, err := f.file.ReadAt(dest, off)
	if err != nil && n > 0 {
		return n, nil
	}
	return n, err
}

func (f *winOpenFile) write(data []byte, off int64) (int, error) {
	if f.appendMode {
		// Windows defines an OVERLAPPED offset of -1 as
		// FILE_WRITE_TO_END_OF_FILE. The kernel selects EOF atomically, so
		// concurrent O_APPEND handles cannot query the same size and overlap.
		// winOpenFile handles are synchronous, so WriteFile completes before
		// this stack-owned OVERLAPPED goes out of scope.
		var written uint32
		overlap := windows.Overlapped{Offset: ^uint32(0), OffsetHigh: ^uint32(0)}
		err := windows.WriteFile(windows.Handle(f.file.Fd()), data, &written, &overlap)
		runtime.KeepAlive(f.file)
		return int(written), err
	}
	return f.file.WriteAt(data, off)
}
