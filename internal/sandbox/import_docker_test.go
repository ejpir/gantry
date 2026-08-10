package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCloneImportedRWLayerIsPrivate(t *testing.T) {
	dir := t.TempDir()
	source := dir + "/source.ext4"
	destination := dir + "/gantry/private.ext4"
	want := bytes.Repeat([]byte("rwlayer"), 1024)
	if err := os.WriteFile(source, want, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := cloneImportedRWLayer(source, destination); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("writing the imported layer changed its source")
	}
	if err := cloneImportedRWLayer(source, destination); err == nil {
		t.Fatal("second clone should not overwrite a persistent layer")
	}
}

// taskLogLine renders a daemon.log line the way the reference daemon
// writes it: a JSON object whose msg field carries a Go-quoted rootfs
// mount spec.
func taskLogLine(containerID, rootfsSpec string) string {
	msg := fmt.Sprintf(`time=2026-08-03T00:58:38.006+02:00 level=INFO msg=\"creating container task\" ns=docker id=%s component=shim runtime=io.containerd.nerdbox.v1 rootfs=%s stdin=/x/fifos/stdin`, containerID, strconv.Quote(rootfsSpec))
	b, _ := json.Marshal(map[string]string{"time": "2026-08-03T00:58:38.006284+02:00", "level": "INFO", "msg": msg, "source": "shim"})
	return string(b)
}

const sampleRootfsSpec = `[type:"ext4"  source:"/root/io.containerd.snapshotter.v1.erofs/snapshots/27/rwlayer.img"  options:"rw"  options:"loop"  options:"noinit_itable" type:"erofs"  source:"/root/io.containerd.snapshotter.v1.erofs/snapshots/26/fsmeta.erofs"  options:"ro"  options:"loop"  options:"device=/root/io.containerd.snapshotter.v1.erofs/snapshots/1/layer.erofs"  options:"device=/root/io.containerd.snapshotter.v1.erofs/snapshots/2/layer.erofs"  options:"device=/root/io.containerd.snapshotter.v1.erofs/snapshots/3/layer.erofs" type:"format/mkdir/overlay"  source:"overlay"  options:"X-containerd.mkdir.path={{ mount 0 }}/upper:0755"  options:"workdir={{ mount 0 }}/work"  options:"upperdir={{ mount 0 }}/upper"  options:"lowerdir={{ mount 1 }}"]`

func TestParseTaskRootfs(t *testing.T) {
	cid := "e5cb6f10b02d2183ea50fee768daca6cc12a7acdafc2ad945557c92331d5f36d"
	log := taskLogLine(cid, sampleRootfsSpec)
	ls, rwlayer, err := parseTaskRootfs(log, cid)
	if err != nil {
		t.Fatal(err)
	}
	if rwlayer != "/root/io.containerd.snapshotter.v1.erofs/snapshots/27/rwlayer.img" {
		t.Errorf("rwlayer = %s", rwlayer)
	}
	if ls.FSMeta != "/root/io.containerd.snapshotter.v1.erofs/snapshots/26/fsmeta.erofs" {
		t.Errorf("fsmeta = %s", ls.FSMeta)
	}
	if len(ls.Layers) != 3 {
		t.Fatalf("layers = %v", ls.Layers)
	}
	for i, n := range []string{"1", "2", "3"} {
		want := "/root/io.containerd.snapshotter.v1.erofs/snapshots/" + n + "/layer.erofs"
		if ls.Layers[i] != want {
			t.Errorf("layer %d = %s, want %s (order is load-bearing)", i, ls.Layers[i], want)
		}
	}
}

func TestParseTaskRootfsLastBootWins(t *testing.T) {
	cid := "abcd1234"
	old := strings.Replace(sampleRootfsSpec, "snapshots/27", "snapshots/10", 1)
	log := taskLogLine(cid, old) + "\n" + taskLogLine(cid, sampleRootfsSpec)
	_, rwlayer, err := parseTaskRootfs(log, cid)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rwlayer, "snapshots/27") {
		t.Fatalf("want the most recent boot's rwlayer, got %s", rwlayer)
	}
}

func TestParseTaskRootfsNotFound(t *testing.T) {
	if _, _, err := parseTaskRootfs(taskLogLine("otherid", sampleRootfsSpec), "missing"); err == nil {
		t.Fatal("want an error when the container never booted")
	}
}

func TestParseDockerPorts(t *testing.T) {
	specs, err := parseDockerPorts([]byte(`[{"host_ip":"127.0.0.1","host_port":8000,"sandbox_port":18000,"protocol":"tcp"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0] != "127.0.0.1:8000:18000" {
		t.Fatalf("specs = %v", specs)
	}
	// wildcard bind stays wide; udp keeps its suffix
	specs, err = parseDockerPorts([]byte(`[{"host_ip":"0.0.0.0","host_port":53,"sandbox_port":5353,"protocol":"udp"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0] != "53:5353/udp" {
		t.Fatalf("specs = %v", specs)
	}
}

func TestLoadImportedPorts(t *testing.T) {
	root := t.TempDir()
	if ports, err := loadImportedPorts(root, "dev"); err != nil || ports != nil {
		t.Fatalf("missing optional ports file = %v, %v", ports, err)
	}

	dir := filepath.Join(root, "runtimes", "ports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, sha256Hex("dev")+".json")
	if err := os.WriteFile(path, []byte(`[{"host_ip":"127.0.0.1","host_port":8000,"sandbox_port":18000,"protocol":"tcp"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	ports, err := loadImportedPorts(root, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0] != "127.0.0.1:8000:18000" {
		t.Fatalf("loaded ports = %v", ports)
	}

	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadImportedPorts(root, "dev"); err == nil || !strings.Contains(err.Error(), "ports:") {
		t.Fatalf("malformed ports error = %v", err)
	}
}

func TestParseDockerRuntime(t *testing.T) {
	rt, err := parseDockerRuntime([]byte(`{"ID":"8eebe181-5c8e-4adb-8d06-9fb9e2abc4f0","Spec":{"WorkspaceDir":"/Users/x","RuntimeName":"codex-dev","AgentName":"codex","Template":"docker.io/library/codex-dev:v1","Services":{"Domains":{"api.github.com":"github","api.openai.com":"openai"},"AllowedDomains":["deb.debian.org"]}},"State":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if rt.Spec.RuntimeName != "codex-dev" || rt.Spec.WorkspaceDir != "/Users/x" || rt.Spec.Template != "docker.io/library/codex-dev:v1" {
		t.Fatalf("parsed %+v", rt.Spec)
	}
	pol, err := importedNetpol(rt)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Default      string   `json:"default"`
		AllowDomains []string `json:"allowDomains"`
	}
	if err := json.Unmarshal(pol, &p); err != nil {
		t.Fatal(err)
	}
	if p.Default != "allow" {
		t.Errorf("default = %s", p.Default)
	}
	want := []string{"api.github.com", "api.openai.com", "deb.debian.org"}
	if len(p.AllowDomains) != len(want) {
		t.Fatalf("allowDomains = %v", p.AllowDomains)
	}
	for i := range want {
		if p.AllowDomains[i] != want[i] {
			t.Errorf("allowDomains[%d] = %s, want %s (sorted)", i, p.AllowDomains[i], want[i])
		}
	}
}

func TestWriteImportCommands(t *testing.T) {
	var output bytes.Buffer
	writeImportCommands(&output)
	got := output.String()
	for _, want := range []string{
		"COMMAND", "DESCRIPTION",
		"gantry import <name>",
		"gantry import <name> --dry-run",
		"gantry import <name> --as <new-name>",
		"gantry import <name> --workspace-owner <owner>",
		"gantry import --help",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("import command help missing %q:\n%s", want, got)
		}
	}
}

func TestDockerPortsAttributionHash(t *testing.T) {
	// The ports file is named sha256(<runtime name>) — verified against
	// the reference store layout.
	if got := sha256Hex("codex-dev"); got != "ab13da902099dbed35e60c72f6188522d324d576a1e88c3b5ebb0549aedc0c2a" {
		t.Fatalf("sha256(codex-dev) = %s", got)
	}
}

func TestImportedWorkspaceOwner(t *testing.T) {
	if got, err := importedWorkspaceOwner("auto", nil); err != nil || got != "" {
		t.Fatalf("root/default auto owner = %q, %v", got, err)
	}
	if got, err := importedWorkspaceOwner("1000:1001", nil); err != nil || got != ",uid=1000,gid=1001" {
		t.Fatalf("explicit owner = %q, %v", got, err)
	}
	if _, err := importedWorkspaceOwner("agent", nil); err == nil {
		t.Fatal("named import owner was accepted")
	}
}

func TestDockerSourceQuiescent(t *testing.T) {
	// Only a fully stopped container has a guaranteed-unattached writable
	// layer; paused keeps a frozen guest with dirty ext4 state attached.
	for state, want := range map[string]bool{
		"exited": true, "created": true, "Exited": true,
		"running": false, "paused": false, "restarting": false,
		"removing": false, "dead": false, "": false,
	} {
		if got := dockerSourceQuiescent(state); got != want {
			t.Errorf("dockerSourceQuiescent(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestContainerPathsOverlap(t *testing.T) {
	hub := "/run/gantry/shares"
	for target, want := range map[string]bool{
		"/run/gantry/shares":      true,  // exact
		"/run/gantry":             true,  // parent
		"/run":                    true,  // grandparent
		"/":                       true,  // root
		"/run/gantry/shares/code": true,  // child
		"/run/gantry/sharesx":     false, // prefix but not a path component
		"/host/code":              false,
		"/data":                   false,
	} {
		if got := containerPathsOverlap(target, hub); got != want {
			t.Errorf("containerPathsOverlap(%q, hub) = %v, want %v", target, got, want)
		}
	}
}
