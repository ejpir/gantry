package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteMainHelpListsCommands(t *testing.T) {
	var output bytes.Buffer
	writeMainHelp(&output)
	got := output.String()
	for _, want := range []string{
		"gantry start <name>",
		"gantry exec <name>",
		"gantry tui",
		"gantry image <verb>",
		"gantry share <verb>",
		"gantry ports <verb>",
		"gantry net-policy <verb>",
		"gantry import [<name>]",
		"gantry stop <name>",
		"gantry resume <name>",
		"gantry delete <name>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("top-level help missing %q:\n%s", want, got)
		}
	}
}
