package sandbox

import (
	"testing"

	"github.com/ejpir/gantry/internal/image"
)

func TestMCPHelperLaunchesRootBeforeConfiguredDrop(t *testing.T) {
	original := &image.Config{
		User: "app", UID: 1000, GID: 2000, WorkingDir: "/work",
		Env: []string{"HOME=/home/app"},
	}
	launcher := mcpLauncherImageConfig(original)
	if launcher.User != "root" || launcher.UID != 0 || launcher.GID != 0 {
		t.Fatalf("MCP launcher identity = %q %d:%d", launcher.User, launcher.UID, launcher.GID)
	}
	if launcher.WorkingDir != "/work" || len(launcher.Env) != 1 {
		t.Fatalf("MCP launcher dropped image execution context: %+v", launcher)
	}
	if original.User != "app" || original.UID != 1000 || original.GID != 2000 {
		t.Fatalf("MCP launcher mutated saved image config: %+v", original)
	}
}
