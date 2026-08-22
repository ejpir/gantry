//go:build linux || darwin

package worker

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejpir/gantry/internal/workerproto"
)

type trackedCloser struct{ closed bool }

func (closer *trackedCloser) Close() error {
	closer.closed = true
	return nil
}

func TestLaunchRejectsSparseUnixCapabilityTableWithoutTakingOwnership(t *testing.T) {
	capability, err := os.CreateTemp(t.TempDir(), "capability-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = capability.Close() }()
	exitCloser := &trackedCloser{}
	child, err := Launch(LaunchSpec{
		Role:           workerproto.RoleMCP,
		EntryPoint:     "_mcp-worker",
		Channels:       []string{"control"},
		InheritedFiles: []InheritedFile{{Slot: 5, File: capability}}, // slot 4 is missing
		DiagnosticPath: filepath.Join(t.TempDir(), "worker-mcp.log"),
		Confinement:    "off",
		ExitClosers:    []io.Closer{exitCloser},
	})
	if child != nil || err == nil || !strings.Contains(err.Error(), "is not dense") {
		t.Fatalf("Launch result child=%v err=%v, want sparse-table refusal", child, err)
	}
	if exitCloser.closed {
		t.Fatal("failed launch took ownership of role exit closer")
	}
}
