//go:build windows

// GANTRY PATCH: Windows passthrough reads return memory buffers; there is no
// host file descriptor splice path.
package fuse

type seekableResult interface {
	Seekable() (fd uintptr, off int64, sz int)
}

type statefulResult interface {
	Stateful() (fd uintptr, sz int)
}

type readResultData struct{ Data []byte }

func (r *readResultData) Size() int { return len(r.Data) }
func (r *readResultData) Done()     {}
func (r *readResultData) Bytes(buf []byte) ([]byte, Status) {
	return r.Data, OK
}

func ReadResultData(b []byte) ReadResult { return &readResultData{b} }
