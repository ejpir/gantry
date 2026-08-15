package sandbox

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const (
	// A worker or guest controls the bytes written to these streams. Keep a
	// useful postmortem tail without turning a diagnostic path into an
	// unbounded disk-allocation capability.
	boundedLogMaxBytes    = int64(2 << 20)
	boundedLogRetainBytes = int64(1 << 20)
	boundedLogBurstBytes  = 256 << 10
	boundedLogRateWindow  = time.Second
)

// boundedLogPipe is a one-way capability: an untrusted producer receives
// only Writer, while the trusted supervisor owns the regular log file. The
// reader drains at a bounded rate and compacts the file in place, retaining
// the newest bytes. A hostile producer can therefore block itself, but cannot
// make the supervisor allocate or write without bound.
type boundedLogPipe struct {
	reader *os.File
	writer *os.File
	done   chan struct{}

	closeWriter sync.Once
	closeReader sync.Once

	mu  sync.Mutex
	err error
}

func newBoundedLogPipe(path string) (*boundedLogPipe, error) {
	sink, err := newBoundedLogSink(path)
	if err != nil {
		return nil, err
	}
	pipe, err := newBoundedLogPipeWithSink(sink)
	if err != nil {
		_ = sink.Close()
	}
	return pipe, err
}

func newBoundedLogPipeWithSink(sink io.WriteCloser) (*boundedLogPipe, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	pipe := &boundedLogPipe{
		reader: reader,
		writer: writer,
		done:   make(chan struct{}),
	}
	go pipe.drain(sink)
	return pipe, nil
}

func (p *boundedLogPipe) Writer() *os.File { return p.writer }

// ReleaseWriter drops the supervisor's duplicate after a successful spawn.
// EOF then follows worker death even if the caller intentionally lets the
// broker self-own until that point.
func (p *boundedLogPipe) ReleaseWriter() {
	p.closeWriter.Do(func() { _ = p.writer.Close() })
}

func (p *boundedLogPipe) drain(sink io.WriteCloser) {
	err := copyLogAtRate(sink, p.reader)
	err = errors.Join(err, sink.Close())
	// Normal EOF and sink failures both revoke the read capability. Without
	// this, every completed worker leaves a supervisor descriptor behind; on a
	// sink failure the producer would also keep writing into an undrained pipe.
	p.closeReader.Do(func() { _ = p.reader.Close() })
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
	close(p.done)
}

// Close normally drains the final pipe buffer. The timeout is only a guard
// for an unexpected duplicate writer; closing the reader then makes the
// producer's next write fail instead of hanging daemon teardown.
func (p *boundedLogPipe) Close() error {
	p.ReleaseWriter()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-p.done:
	case <-timer.C:
		p.closeReader.Do(func() { _ = p.reader.Close() })
		<-p.done
	}
	p.closeReader.Do(func() { _ = p.reader.Close() })
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func copyLogAtRate(dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32<<10)
	remaining := boundedLogBurstBytes
	window := time.Now()
	for {
		if remaining == 0 {
			delay := boundedLogRateWindow - time.Since(window)
			if delay > 0 {
				time.Sleep(delay)
			}
			window = time.Now()
			remaining = boundedLogBurstBytes
		}
		limit := len(buf)
		if remaining < limit {
			limit = remaining
		}
		n, readErr := src.Read(buf[:limit])
		if n > 0 {
			remaining -= n
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, os.ErrClosed) {
				return nil
			}
			return readErr
		}
	}
}

type boundedLogSink struct {
	file    *os.File
	size    int64
	scratch []byte
}

func newBoundedLogSink(path string) (io.WriteCloser, error) {
	if path == "" {
		return discardWriteCloser{}, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	sink := &boundedLogSink{file: file, size: info.Size()}
	if sink.size > boundedLogMaxBytes {
		if err := sink.compact(); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return nil, err
	}
	return sink, nil
}

func (s *boundedLogSink) Write(data []byte) (int, error) {
	originalLen := len(data)
	if int64(len(data)) > boundedLogMaxBytes-boundedLogRetainBytes {
		data = data[len(data)-int(boundedLogMaxBytes-boundedLogRetainBytes):]
	}
	if s.size+int64(len(data)) > boundedLogMaxBytes {
		if err := s.compact(); err != nil {
			return 0, err
		}
	}
	written, err := s.file.Write(data)
	s.size += int64(written)
	if err != nil {
		return written, err
	}
	// The prefix was deliberately discarded, not partially accepted. Report
	// the original length so io.Copy does not retry attacker-controlled data.
	return originalLen, nil
}

func (s *boundedLogSink) compact() error {
	keep := s.size
	if keep > boundedLogRetainBytes {
		keep = boundedLogRetainBytes
	}
	if int64(cap(s.scratch)) < keep {
		s.scratch = make([]byte, keep)
	}
	tail := s.scratch[:keep]
	if keep != 0 {
		if _, err := s.file.ReadAt(tail, s.size-keep); err != nil {
			return err
		}
	}
	if err := s.file.Truncate(0); err != nil {
		return err
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if len(tail) != 0 {
		if _, err := s.file.Write(tail); err != nil {
			return err
		}
	}
	s.size = keep
	return nil
}

func (s *boundedLogSink) Close() error { return s.file.Close() }

type discardWriteCloser struct{}

func (discardWriteCloser) Write(data []byte) (int, error) { return len(data), nil }
func (discardWriteCloser) Close() error                   { return nil }
