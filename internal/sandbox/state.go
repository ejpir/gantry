package sandbox

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/ejpir/gantry/internal/sandbox/boundedlog"
	"github.com/ejpir/gantry/internal/sandbox/layout"
)

// Sandbox lifecycle: create/start/stop/ls/delete + exec.
// A sandbox is a long-lived VMM daemon holding the single
// vsock dial-back ttrpc connection vminitd makes per VM lifetime
// (dialBackListener dials exactly once). `gantry exec <name>` is a thin
// client; the daemon multiplexes sessions over that one connection (ttrpc
// streams are independent, so concurrent exec sessions are fine).
//
// Where that state lives on disk, and whether the daemon owning it is still
// alive, is the layout package's job.

// ValidateSandboxName rejects names that are empty, overlong, pure dots
// (path traversal — `delete` feeds the joined path to os.RemoveAll) or
// contain anything but letters, digits and ._-. The CLI dispatch layer
// (main.go) turns the error into an exit code; the library itself never
// exits.
func ValidateSandboxName(name string) error { return layout.ValidateName(name) }

func dumpTailTo(w io.Writer, path string) {
	b, _, err := boundedlog.ReadTail(path, 4096)
	if err != nil || len(b) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "---- last bytes of %s ----\n%s\n----\n", filepath.Base(path), b)
}
