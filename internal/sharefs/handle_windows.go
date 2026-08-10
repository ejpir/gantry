//go:build windows

package sharefs

import (
	"context"
	"io"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/windows"
)

type winShareFile struct {
	wf      *winOpenFile
	backend *winExportFS
	export  *Export
	node    *winShareNode
}

func (f *winShareFile) belongsTo(n *winShareNode) bool {
	return f != nil && n != nil && f.wf != nil && f.backend == n.backend &&
		f.export == n.export && f.node == n
}

func (f *winShareFile) available() syscall.Errno {
	if f.export == nil || !f.export.usable() {
		return syscall.ESTALE
	}
	return 0
}

func (f *winShareFile) mutable() syscall.Errno {
	if f.export == nil {
		return syscall.ESTALE
	}
	return f.export.mutable()
}

var _ fs.FileReader = (*winShareFile)(nil)

func (f *winShareFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if errno := f.available(); errno != 0 {
		return nil, errno
	}
	n, err := f.wf.read(dest, off)
	if err != nil && err != io.EOF {
		return nil, ntStatusErrno(err)
	}
	return fuse.ReadResultData(dest[:n]), 0
}

var _ fs.FileWriter = (*winShareFile)(nil)

func (f *winShareFile) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	if errno := f.mutable(); errno != 0 {
		return 0, errno
	}
	n, err := f.wf.write(data, off)
	return uint32(n), ntStatusErrno(err)
}

var _ fs.FileGetattrer = (*winShareFile)(nil)

func (f *winShareFile) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	info, errno := f.backend.infoForHandle(windows.Handle(f.wf.file.Fd()))
	if errno == 0 {
		out.Attr = info.attr
		out.SetTimeout(0)
	}
	return errno
}

var _ fs.FileSetattrer = (*winShareFile)(nil)

func (f *winShareFile) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if errno := f.mutable(); errno != 0 {
		return errno
	}
	attr, errno := f.backend.setattr("", f.wf, in)
	if errno == 0 {
		out.Attr = attr
		out.SetTimeout(0)
	}
	return errno
}

var _ fs.FileFlusher = (*winShareFile)(nil)

func (f *winShareFile) Flush(ctx context.Context) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	if !f.wf.writable {
		// FlushFileBuffers requires write access; a flush after reads on a
		// read-only handle is a no-op, not an access-denied error.
		return 0
	}
	return ntStatusErrno(windows.FlushFileBuffers(windows.Handle(f.wf.file.Fd())))
}

var _ fs.FileFsyncer = (*winShareFile)(nil)

func (f *winShareFile) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	if errno := f.available(); errno != 0 {
		return errno
	}
	if !f.wf.writable {
		// same FlushFileBuffers access requirement as Flush
		return 0
	}
	return ntStatusErrno(windows.FlushFileBuffers(windows.Handle(f.wf.file.Fd())))
}

var _ fs.FileReleaser = (*winShareFile)(nil)

func (f *winShareFile) Release(ctx context.Context) syscall.Errno {
	return ntStatusErrno(f.wf.close())
}

var _ fs.FileLseeker = (*winShareFile)(nil)

func (f *winShareFile) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
	if errno := f.available(); errno != 0 {
		return 0, errno
	}
	n, err := f.wf.file.Seek(int64(off), int(whence))
	return uint64(n), ntStatusErrno(err)
}

var _ fs.FileIoctler = (*winShareFile)(nil)

// Ioctl is default-deny, mirroring the Unix hub: no mutating host ioctls
// may cross the boundary. Without an explicit implementation the bridge
// reported EIO, which misreads as a backend failure instead of policy.
func (f *winShareFile) Ioctl(ctx context.Context, cmd uint32, arg uint64, input []byte, output []byte) (int32, syscall.Errno) {
	return 0, fuse.ErrnoFromStatus(fuse.ENOTSUP)
}
