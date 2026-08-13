package gutil

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressPrinterRepaintsTerminalDownload(t *testing.T) {
	var output bytes.Buffer
	progress := newProgressPrinter(&output, "gantry start: ", true)
	progress.Printf("downloading kernel from release")
	progress.Printf("downloading kernel [····] 0%%")
	progress.Printf("downloading kernel [====] 100%%")
	progress.Printf("staged /cache/kernel")

	got := output.String()
	if strings.Count(got, "\n") != 3 {
		t.Fatalf("terminal progress used %d lines, want intro, progress, and staged:\n%q", strings.Count(got, "\n"), got)
	}
	if !strings.Contains(got, "\r\x1b[2Kgantry start: downloading kernel [====] 100%") {
		t.Fatalf("terminal progress was not repainted: %q", got)
	}
}

func TestProgressPrinterKeepsPipeUpdatesDelimited(t *testing.T) {
	var output bytes.Buffer
	progress := newProgressPrinter(&output, "gantry start: ", false)
	progress.Printf("downloading kernel [····] 0%%")
	progress.Printf("downloading kernel [====] 100%%")

	got := output.String()
	if strings.Count(got, "\n") != 2 || strings.Contains(got, "\r") {
		t.Fatalf("pipe progress is not line-delimited: %q", got)
	}
}

func TestProgressPrinterFinishTerminatesActiveRow(t *testing.T) {
	var output bytes.Buffer
	progress := newProgressPrinter(&output, "", true)
	progress.Printf("downloading kernel [==··] 50%%")
	progress.Finish()
	progress.Finish()
	if strings.Count(output.String(), "\n") != 1 {
		t.Fatalf("Finish output = %q, want exactly one terminating newline", output.String())
	}
}
