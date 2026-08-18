package boundedlog

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// diagnosticTailBytes is how much of a worker's log an error carries. It is a
// diagnostic excerpt, not the log: the full file stays on disk.
const diagnosticTailBytes = 16 << 10

// ReadTail allocates in proportion to the requested tail, never the file.
// Logs are attacker-influenced and may also predate the bounded log broker.
func ReadTail(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	end, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, limit))
}

func DiagnosticTail(role, path string) error {
	tail, err := ReadTail(path, diagnosticTailBytes)
	if err != nil {
		return fmt.Errorf("read %s diagnostics: %w", role, err)
	}
	if len(tail) == 0 {
		return nil
	}
	// A tail may begin in the middle of a line. Mark that explicitly rather
	// than making the fragment look like a complete worker diagnostic.
	if tail[0] != '\n' {
		tail = append([]byte("..."), tail...)
	}
	return errors.New(role + " diagnostics:\n" + string(tail))
}
