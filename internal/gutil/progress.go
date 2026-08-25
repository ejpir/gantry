package gutil

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// ProgressPrinter writes ordinary messages as lines and repaints byte-level
// download progress in place when output is a terminal. When output is a pipe
// (including the dashboard subprocess), every update remains newline-delimited
// so the consumer can stream it independently.
type ProgressPrinter struct {
	mu       sync.Mutex
	writer   io.Writer
	prefix   string
	inPlace  bool
	painting bool
}

// NewProgressPrinter creates a progress printer for file.
func NewProgressPrinter(file *os.File, prefix string) *ProgressPrinter {
	return newProgressPrinter(file, prefix, term.IsTerminal(int(file.Fd())))
}

func newProgressPrinter(writer io.Writer, prefix string, inPlace bool) *ProgressPrinter {
	return &ProgressPrinter{writer: writer, prefix: prefix, inPlace: inPlace}
}

// Printf implements the progress callback used by guest assets and image
// resolution.
func (p *ProgressPrinter) Printf(format string, values ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	message := fmt.Sprintf(format, values...)
	if p.inPlace && isByteProgress(message) {
		_, _ = fmt.Fprintf(p.writer, "\r\x1b[2K%s%s", p.prefix, message)
		p.painting = true
		return
	}
	if p.painting {
		_, _ = fmt.Fprintln(p.writer)
		p.painting = false
	}
	_, _ = fmt.Fprintf(p.writer, "%s%s\n", p.prefix, message)
}

// Finish terminates an in-place progress row before callers print an error or
// otherwise stop reporting.
func (p *ProgressPrinter) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.painting {
		_, _ = fmt.Fprintln(p.writer)
		p.painting = false
	}
}

func isByteProgress(message string) bool {
	return (strings.HasPrefix(message, "downloading ") ||
		strings.HasPrefix(message, "creating persistent disk ") ||
		strings.HasPrefix(message, "exporting ") ||
		strings.HasPrefix(message, "writing OCI archive ")) &&
		strings.Contains(message, "[") && strings.Contains(message, "]")
}
