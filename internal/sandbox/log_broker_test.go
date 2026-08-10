package sandbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failingLogSink struct {
	err    error
	closed bool
}

func (s *failingLogSink) Write([]byte) (int, error) { return 0, s.err }
func (s *failingLogSink) Close() error {
	s.closed = true
	return nil
}

func TestBoundedLogPipeRetainsRecentBytesWithinCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.log")
	sink, err := newBoundedLogSink(path)
	if err != nil {
		t.Fatal(err)
	}

	chunk := bytes.Repeat([]byte{'a'}, 32<<10)
	for written := int64(0); written < boundedLogMaxBytes*2; written += int64(len(chunk)) {
		if _, err := sink.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	marker := []byte("newest-diagnostic-marker\n")
	if _, err := sink.Write(marker); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > boundedLogMaxBytes {
		t.Fatalf("bounded log grew to %d bytes, limit %d", info.Size(), boundedLogMaxBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, marker) {
		t.Fatalf("bounded log lost newest marker; tail=%q", data[max(0, len(data)-64):])
	}
}

func TestBoundedLogPipeWriterIsNotRegularFile(t *testing.T) {
	pipe, err := newBoundedLogPipe(filepath.Join(t.TempDir(), "worker.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipe.Close() }()

	info, err := pipe.Writer().Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().IsRegular() {
		t.Fatal("untrusted writer received a regular-file description")
	}
	if err := pipe.Writer().Truncate(1 << 30); err == nil {
		t.Fatal("pipe writer unexpectedly allowed truncation")
	}
}

func TestBoundedLogPipeSinkFailureRevokesReaderAndSurfacesError(t *testing.T) {
	wantErr := errors.New("diagnostic disk failed")
	sink := &failingLogSink{err: wantErr}
	pipe, err := newBoundedLogPipeWithSink(sink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pipe.Writer().Write([]byte("trigger")); err != nil {
		t.Fatal(err)
	}
	<-pipe.done
	if _, err := pipe.reader.Stat(); err == nil {
		t.Fatal("drain completion left its read descriptor open")
	}
	if !sink.closed {
		t.Fatal("drain failure did not close its sink")
	}
	if err := pipe.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close error = %v, want %v", err, wantErr)
	}
	if _, err := pipe.Writer().Write([]byte("after failure")); err == nil {
		t.Fatalf("write after sink failure = %v, want a closed-pipe error", err)
	}
}
