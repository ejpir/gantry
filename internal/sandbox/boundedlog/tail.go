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
// truncated reports whether the file is larger than the returned tail.
func ReadTail(path string, limit int64) (tail []byte, truncated bool, err error) {
	if limit <= 0 {
		return nil, false, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	end, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, false, err
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, false, err
	}
	b, err := io.ReadAll(io.LimitReader(file, limit))
	return b, start > 0, err
}

func DiagnosticTail(role, path string) error {
	tail, truncated, err := ReadTail(path, diagnosticTailBytes)
	if err != nil {
		return fmt.Errorf("read %s diagnostics: %w", role, err)
	}
	if len(tail) == 0 {
		return nil
	}
	// A genuinely truncated tail may begin in the middle of a line. Mark
	// exactly that case; a small log returned whole is not a fragment.
	if truncated && tail[0] != '\n' {
		tail = append([]byte("..."), tail...)
	}
	return errors.New(role + " diagnostics:\n" + string(tail))
}
