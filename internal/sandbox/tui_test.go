package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTUISandboxes(t *testing.T) {
	t.Setenv("GANTRY_HOME", t.TempDir())
	for _, name := range []string{"zeta", "alpha"} {
		if err := os.MkdirAll(sandboxDir(name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sandboxDir("alpha"), "sandbox.json"), []byte(`{
		"image":"/cache/alpine.erofs",
		"image_ref":"alpine:latest",
		"rw":true,
		"secret_names":["TOKEN"]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadTUISandboxes()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "alpha" || got[1].Name != "zeta" {
		t.Fatalf("sandboxes = %#v, want alpha then zeta", got)
	}
	if got[0].Image != "alpine:latest" || !got[0].RW || got[0].Secrets != "TOKEN" {
		t.Fatalf("alpha metadata = %#v", got[0])
	}
	if got[0].State != "stopped" {
		t.Fatalf("alpha state = %q, want stopped", got[0].State)
	}
}

func TestSandboxTUIRender(t *testing.T) {
	m := newSandboxTUIModel()
	m.loading = false
	m.sandboxes = []tuiSandbox{{Name: "dev", State: "running", PID: 42, Image: "alpine:latest"}}
	view := m.View()
	if !strings.Contains(view.Content, "gantry") || !strings.Contains(view.Content, "dev") || !strings.Contains(view.Content, "RUNNING") {
		t.Fatalf("view does not contain dashboard content: %q", view.Content)
	}
	if !view.AltScreen {
		t.Fatal("dashboard should use the alternate screen")
	}
}
