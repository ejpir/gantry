// Package sshconfig shares OpenSSH quoting and lock-guarded managed-file
// updates between local sandboxes and remote profiles.
package sshconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/gutil"
	"github.com/ejpir/gantry/internal/sandbox/localsec"
)

func ShellCommand(argv ...string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		if runtime.GOOS == "windows" {
			quoted[i] = `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
		} else {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
		}
	}
	return strings.Join(quoted, " ")
}

// ArgvCommand quotes a command for OpenSSH directives, such as
// KnownHostsCommand, that OpenSSH splits directly without a shell. Single
// quotes survive Windows CreateProcess argument decoding; double quotes do not
// when a complete directive is supplied through `ssh -o`. Backslashes are
// doubled because OpenSSH's argv_split treats them as escapes even in quotes.
func ArgvCommand(argv ...string) string {
	quoted := make([]string, len(argv))
	escape := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	for i, arg := range argv {
		quoted[i] = "'" + escape.Replace(arg) + "'"
	}
	return strings.Join(quoted, " ")
}

func QuotePath(path string) string { return `"` + strings.ReplaceAll(path, `\`, `\\`) + `"` }

// GuestCommand preserves argument boundaries across OpenSSH's concatenation
// and the guest's POSIX shell, independently of the client OS.
func GuestCommand(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}

// Update refuses ambiguous markers. Prepending remote blocks is essential:
// OpenSSH takes the first value, so *.box.gantry must precede *.gantry.
func Update(content, begin, end, block string, remove, prepend bool) (string, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	start, finish, starts, finishes, offset := -1, -1, 0, 0, 0
	for _, line := range strings.Split(content, "\n") {
		if line == begin {
			start = offset
			starts++
		}
		if line == end {
			finish = offset
			finishes++
		}
		offset += len(line) + 1
	}
	if starts > 1 || finishes > 1 || (start >= 0) != (finish >= 0) || (start >= 0 && finish < start) {
		return "", errors.New("managed SSH markers are incomplete; repair the file by hand before retrying")
	}
	if start >= 0 {
		finish += len(end)
		if finish < len(content) && content[finish] == '\n' {
			finish++
		}
		content = content[:start] + content[finish:]
	}
	content = strings.TrimRight(content, "\n")
	if !remove {
		if content == "" {
			content = block
		} else if prepend {
			content = block + "\n\n" + content
		} else {
			content += "\n\n" + block
		}
	}
	if content != "" {
		content += "\n"
	}
	return content, nil
}

func Lock(path string) (*os.File, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		lock, err := gutil.TryLockFile(path)
		if err == nil {
			return lock, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for SSH setup lock %s: %w", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func readConfig(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a real regular file", path)
	}
	if err := localsec.SecureRegularFile(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	return string(data), err
}

// Apply updates one block, then keeps the include at the top of ~/.ssh/config.
// Local and remote writers share config.lock and preserve one another's blocks.
func Apply(dir, begin, end, block string, remove, prepend bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	for _, path := range []string{sshDir, dir} {
		if err := localsec.CreateManagerDir(path); err != nil {
			return err
		}
	}
	lock, err := Lock(filepath.Join(dir, "config.lock"))
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	managedPath, mainPath := filepath.Join(dir, "config"), filepath.Join(sshDir, "config")
	managed, err := readConfig(managedPath)
	if err != nil {
		return err
	}
	main, err := readConfig(mainPath)
	if err != nil {
		return err
	}
	next, err := Update(managed, begin, end, block, remove, prepend)
	if err != nil {
		return err
	}
	include := "Include " + QuotePath(managedPath)
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(main, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) != include {
			lines = append(lines, line)
		}
	}
	main = strings.TrimRight(strings.Join(lines, "\n"), "\n")
	if strings.TrimSpace(next) != "" {
		main = include + "\n" + main
	}
	if main != "" {
		main = strings.TrimRight(main, "\n") + "\n"
	}
	for path, content := range map[string]string{managedPath: next, mainPath: main} {
		if err := atomicfile.WriteFileDurable(path, []byte(content), 0o600); err != nil {
			return err
		}
		if err := localsec.SecureRegularFile(path); err != nil {
			return err
		}
	}
	return nil
}
