package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/layout"
	"github.com/ejpir/gantry/internal/secret"
)

// CmdTransientExec runs a one-shot session through the same daemon and worker
// topology as a named sandbox. The randomly named state directory exists only
// for the command's lifetime, but using the normal supervisor path keeps
// auto/required process isolation honest and gives one-shot sessions the same
// broker, share, policy, and shutdown semantics as long-lived sandboxes.
func CmdTransientExec(cfg config.RunConfig, secrets map[string]secret.Value, args []string, showConsole bool) (status int) {
	name, err := transientSandboxName()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gantry exec:", err)
		return 1
	}

	if showConsole {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			followFile(ctx, filepath.Join(layout.Dir(name), "console.log"), os.Stderr)
		}()
		defer func() {
			cancel()
			<-done
		}()
	}
	// Register cleanup after the follower so LIFO defer order keeps console
	// streaming through graceful VM shutdown, then stops the follower.
	defer func() {
		if err := deleteSandbox(name); err != nil {
			fmt.Fprintln(os.Stderr, "gantry exec: cleanup:", err)
			if status == 0 {
				status = 1
			}
		}
	}()

	if status = launchSandboxMode(name, cfg, secrets, true, true); status != 0 {
		return status
	}
	return CmdSandboxExec(name, append([]string{"--"}, args...))
}

func transientSandboxName() (string, error) {
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate transient sandbox name: %w", err)
	}
	return ".exec-" + hex.EncodeToString(suffix[:]), nil
}

// followFile streams a regular file until ctx is canceled. It is used only by
// the explicit -console path, so normal startup performs no polling or extra
// I/O. A final drain after cancellation preserves shutdown diagnostics.
func followFile(ctx context.Context, path string, dst io.Writer) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	var file *os.File
	defer func() {
		if file != nil {
			_ = rewindIfTruncated(file)
			_, _ = io.Copy(dst, file)
			_ = file.Close()
		}
	}()
	buf := make([]byte, 32<<10)
	for {
		if file == nil {
			opened, err := os.Open(path)
			if err == nil {
				file = opened
			}
		} else {
			if err := rewindIfTruncated(file); err != nil {
				_ = file.Close()
				file = nil
				continue
			}
			for {
				n, err := file.Read(buf)
				if n > 0 {
					_, _ = dst.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// rewindIfTruncated follows an in-place bounded-log compaction. Without this
// check a follower whose offset was beyond the compacted EOF would wait there
// forever and miss all subsequent output.
func rewindIfTruncated(file *os.File) error {
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() < offset {
		_, err = file.Seek(0, io.SeekStart)
	}
	return err
}
