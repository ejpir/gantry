//go:build windows

// GANTRY PATCH: only ProtocolServer is used on Windows. Local kernel mounts
// and /dev/fuse serving are intentionally excluded.
package fuse

import (
	"log"
	"math"
	"runtime"
	"strings"
)

const (
	defaultMaxWrite = 128 * 1024
	_MAX_NAME_LEN   = 20
)

type Server struct{}

type retrieveCacheRequest struct {
	nodeid uint64
	offset uint64
	dest   []byte
	n      int
	st     Status
	ready  chan struct{}
}

func (s *Server) DeleteNotify(parent uint64, child uint64, name string) Status {
	return ENOSYS
}
func (s *Server) EntryNotify(parent uint64, name string) Status { return ENOSYS }
func (s *Server) InodeNotify(node uint64, off int64, length int64) Status {
	return ENOSYS
}
func (s *Server) InodeRetrieveCache(node uint64, offset int64, dest []byte) (int, Status) {
	return 0, ENOSYS
}
func (s *Server) InodeNotifyStoreCache(node uint64, offset int64, data []byte) Status {
	return ENOSYS
}
func (s *Server) PruneNotify(ids []uint64) Status { return ENOSYS }

func getMaxWrite() int { return defaultMaxWrite }

func (o *MountOptions) setDefaults(fs RawFileSystem) {
	if o.Logger == nil {
		o.Logger = log.Default()
	}
	if o.MaxWrite < 0 {
		o.MaxWrite = 0
	}
	if o.MaxWrite == 0 {
		o.MaxWrite = defaultMaxWrite
	}
	if kernelMaxWrite := getMaxWrite(); o.MaxWrite > kernelMaxWrite {
		o.MaxWrite = kernelMaxWrite
	}
	if o.MaxInflightRequestBytes <= 0 {
		o.MaxInflightRequestBytes = math.MaxInt
	}
	if o.MaxStackDepth == 0 {
		o.MaxStackDepth = 1
	}
	if o.Name == "" {
		name := fs.String()
		l := min(len(name), _MAX_NAME_LEN)
		o.Name = strings.Replace(name[:l], ",", ";", -1)
	}
	if o.PanicHandler == nil {
		logger := o.Logger
		o.PanicHandler = func(obj any) Status {
			return defaultPanicHandler(logger, obj)
		}
	}
	for _, s := range []struct {
		flag bool
		mask uint64
	}{
		{o.SyncRead, CAP_ASYNC_READ},
		{o.DisableReadDirPlus, CAP_READDIRPLUS},
		{!o.IDMappedMount, CAP_ALLOW_IDMAP},
	} {
		if s.flag {
			o.DisabledCapabilities |= s.mask
		}
	}
}

func defaultPanicHandler(logger *log.Logger, obj any) Status {
	const size = 64 << 10
	buf := make([]byte, size)
	buf = buf[:runtime.Stack(buf, false)]
	logger.Printf("panic in FS handler: %v\n%s", obj, buf)
	return EIO
}
