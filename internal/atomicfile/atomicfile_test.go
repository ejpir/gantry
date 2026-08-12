package atomicfile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteFileReplacesWholeContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("new state\n"), 1024)
	if err := WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("contents differ: got %d bytes, want %d", len(got), len(want))
	}
}

func TestWriteCallbackErrorKeepsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("render failed")
	err := Write(path, 0o600, func(writer io.Writer) error {
		_, _ = writer.Write([]byte("partial"))
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != "old" {
		t.Fatalf("existing contents = %q, err = %v", got, readErr)
	}
}

func TestWriteFileDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := WriteFileDurable(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "{}\n" {
		t.Fatalf("contents = %q, err = %v", got, err)
	}
}

func TestMakeDurablePersistsPublishedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MakeDurable(path); err != nil {
		t.Fatal(err)
	}
}

func TestMakeDurableFailureReportsCommittedReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := WriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("directory sync failed")
	original := syncParentDir
	syncParentDir = func(string) error { return wantErr }
	t.Cleanup(func() { syncParentDir = original })

	err := MakeDurable(path)
	if !Committed(err) || !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want committed error wrapping %v", err, wantErr)
	}
}

func TestDurabilityFailureReportsCommittedReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("directory sync failed")
	original := syncParentDir
	syncParentDir = func(string) error { return wantErr }
	t.Cleanup(func() { syncParentDir = original })

	err := WriteFileDurable(path, []byte("new"), 0o600)
	if !Committed(err) || !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want committed error wrapping %v", err, wantErr)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != "new" {
		t.Fatalf("committed contents = %q, err = %v", got, readErr)
	}
}

func TestConcurrentWritersNeverPublishPartialData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot")
	payloads := [][]byte{
		bytes.Repeat([]byte("a"), 32<<10),
		bytes.Repeat([]byte("b"), 32<<10),
		bytes.Repeat([]byte("c"), 32<<10),
	}
	var wg sync.WaitGroup
	for _, payload := range payloads {
		payload := payload
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WriteFile(path, payload, 0o600); err != nil {
				t.Errorf("WriteFile: %v", err)
			}
		}()
	}
	wg.Wait()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range payloads {
		if bytes.Equal(got, payload) {
			return
		}
	}
	t.Fatal("final file is not one complete writer payload")
}

func TestWriteFileRequiresExistingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "state")
	if err := WriteFile(path, nil, 0o600); err == nil {
		t.Fatal("WriteFile unexpectedly created its parent directory")
	}
}
