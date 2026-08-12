// Package atomicfile replaces small files without exposing partial contents.
package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CommitError reports a failure after the replacement became visible. The
// caller must not roll its in-memory state back: doing so would disagree with
// the file readers now observe. The wrapped error means crash durability could
// not be confirmed, not that the old contents remain installed.
type CommitError struct{ Err error }

func (e *CommitError) Error() string {
	if e == nil || e.Err == nil {
		return "replacement committed but durability is uncertain"
	}
	return "replacement committed but durability is uncertain: " + e.Err.Error()
}
func (e *CommitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Committed reports whether err occurred after the replacement commit point.
func Committed(err error) bool {
	var committed *CommitError
	return errors.As(err, &committed)
}

var syncParentDir = syncParent

// WriteFile atomically replaces path with data. The rename is atomic, but the
// update is not forced to stable storage. It is suitable for derived state
// that is rewritten after a crash.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	return Write(path, mode, func(writer io.Writer) error {
		_, err := writer.Write(data)
		return err
	})
}

// WriteFileDurable atomically replaces path with data and asks the operating
// system to persist both the file contents and the directory entry before it
// returns. It is suitable for authoritative configuration.
func WriteFileDurable(path string, data []byte, mode os.FileMode) error {
	return WriteDurable(path, mode, func(writer io.Writer) error {
		_, err := writer.Write(data)
		return err
	})
}

// Write is WriteFile for incrementally produced content. write must not retain
// writer or close it; returning an error aborts the replacement.
func Write(path string, mode os.FileMode, write func(io.Writer) error) error {
	return writeTo(path, mode, false, write)
}

// WriteDurable is the durable form of Write.
func WriteDurable(path string, mode os.FileMode, write func(io.Writer) error) error {
	return writeTo(path, mode, true, write)
}

// MakeDurable persists an atomic replacement that is already visible at path.
// It is useful when a caller can overlap the storage barrier with independent
// work, but must not report success until this function returns. Every failure
// is a CommitError because readers may already observe the replacement.
func MakeDurable(path string) error {
	file, err := openCommittedForSync(path)
	if err != nil {
		return &CommitError{Err: fmt.Errorf("open committed file %s: %w", path, err)}
	}
	if err := file.Sync(); err != nil {
		return &CommitError{Err: errors.Join(
			fmt.Errorf("sync committed file %s: %w", path, err),
			file.Close(),
		)}
	}
	if err := file.Close(); err != nil {
		return &CommitError{Err: fmt.Errorf("close committed file %s: %w", path, err)}
	}
	dir := filepath.Dir(path)
	if err := syncParentDir(dir); err != nil {
		return &CommitError{Err: fmt.Errorf("sync parent directory %s: %w", dir, err)}
	}
	return nil
}

func writeTo(path string, mode os.FileMode, durable bool, write func(io.Writer) error) (retErr error) {
	if write == nil {
		return fmt.Errorf("atomicfile: nil writer")
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tmp := file.Name()
	defer func() {
		if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary file %s: %w", tmp, err))
		}
	}()

	fail := func(operationErr error) error {
		return errors.Join(operationErr, file.Close())
	}
	if err := file.Chmod(mode); err != nil {
		return fail(fmt.Errorf("set temporary file mode: %w", err))
	}
	if err := write(file); err != nil {
		return fail(fmt.Errorf("write temporary file: %w", err))
	}
	if durable {
		if err := file.Sync(); err != nil {
			return fail(fmt.Errorf("sync temporary file: %w", err))
		}
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := replace(tmp, path, durable); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	if durable {
		if err := syncParentDir(dir); err != nil {
			return &CommitError{Err: fmt.Errorf("sync parent directory %s: %w", dir, err)}
		}
	}
	return nil
}
