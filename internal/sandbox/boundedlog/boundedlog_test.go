package boundedlog

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
	sink, err := newSink(path)
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

func TestBoundedLogSinkPreservesPreviousRunTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.log")
	for _, marker := range []string{"first-run-crash\n", "second-run-start\n"} {
		sink, err := newSink(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sink.Write([]byte(marker)); err != nil {
			t.Fatal(err)
		}
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "first-run-crash\nsecond-run-start\n"; got != want {
		t.Fatalf("log across reopen = %q, want %q", got, want)
	}
}

func TestRotatePreviousLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	previous := path + ".previous"
	if err := os.WriteFile(previous, []byte("older"), 0o600); err != nil {
		t.Fatal(err)
	}
	// With no current log, the last useful previous log must survive.
	if err := RotatePrevious(path); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(previous); err != nil || string(data) != "older" {
		t.Fatalf("previous without current = %q, %v", data, err)
	}

	if err := os.WriteFile(path, []byte("latest crash"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RotatePrevious(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("current log still exists after rotation: %v", err)
	}
	if data, err := os.ReadFile(previous); err != nil || string(data) != "latest crash" {
		t.Fatalf("rotated previous = %q, %v", data, err)
	}
}

func TestBoundedLogPipeWriterIsNotRegularFile(t *testing.T) {
	pipe, err := NewPipe(filepath.Join(t.TempDir(), "worker.log"))
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
	pipe, err := newPipeWithSink(sink)
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
