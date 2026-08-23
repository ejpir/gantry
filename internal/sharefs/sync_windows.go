//go:build windows

package sharefs

import (
	"errors"
	"os"
	"syscall"
)

func (backend *winExportFS) trackOpen(file *winOpenFile) *winOpenFile {
	if backend == nil || file == nil {
		return file
	}
	backend.mu.Lock()
	if backend.openFiles == nil {
		backend.openFiles = make(map[*winOpenFile]struct{})
	}
	backend.openFiles[file] = struct{}{}
	file.onClose = func(closed *winOpenFile) {
		backend.mu.Lock()
		delete(backend.openFiles, closed)
		backend.mu.Unlock()
	}
	backend.mu.Unlock()
	return file
}

func (backend *winExportFS) syncOpenFiles() syscall.Errno {
	if backend == nil {
		return syscall.ESTALE
	}
	backend.mu.RLock()
	if backend.root == 0 {
		backend.mu.RUnlock()
		return syscall.ESTALE
	}
	files := make([]*winOpenFile, 0, len(backend.openFiles))
	for file := range backend.openFiles {
		files = append(files, file)
	}
	backend.mu.RUnlock()

	for _, file := range files {
		if file == nil || file.file == nil || !file.writable {
			continue
		}
		if err := file.file.Sync(); err != nil && !errors.Is(err, os.ErrClosed) {
			return ntStatusErrno(err)
		}
	}
	return 0
}

func syncExport(export *Export) syscall.Errno {
	if export == nil || !export.usable() {
		return syscall.ESTALE
	}
	node, ok := export.node.(*winShareNode)
	if !ok || node.backend == nil {
		return syscall.EIO
	}
	return node.backend.syncOpenFiles()
}
