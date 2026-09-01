package sandbox

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/sandbox/config"
	"github.com/ejpir/gantry/internal/sandbox/controlproto"
)

func TestConfigureDevContainersRequiresRestartAndKeepsLiveTarget(t *testing.T) {
	dir := t.TempDir()
	oldEnsureImage, oldVerifyImage := ensureDevContainersImageAsset, verifyDevContainersImageAsset
	oldEnsureLayer, oldCheckPairing := ensureDevContainersRWLayer, checkDevContainersRWPairing
	t.Cleanup(func() {
		ensureDevContainersImageAsset, verifyDevContainersImageAsset = oldEnsureImage, oldVerifyImage
		ensureDevContainersRWLayer, checkDevContainersRWPairing = oldEnsureLayer, oldCheckPairing
	})
	ideImage, ideLayer := filepath.Join(dir, "ide.erofs"), filepath.Join(dir, "ide.ext4")
	ensureDevContainersImageAsset = func(string, func(string, ...any)) (string, error) { return ideImage, nil }
	verifyDevContainersImageAsset = func(string) error { return nil }
	ensureDevContainersRWLayer = func(string, string, uint, func(string, ...any)) (string, []string, error) {
		return ideLayer, nil, nil
	}
	checkDevContainersRWPairing = func(string, string) error { return nil }

	initial := config.RunConfig{SSH: true, Runtime: "crun", MemMB: 512, VCPUs: 1}
	data, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	br := &broker{}
	daemon := &daemonRuntime{name: "dev", store: store, broker: br}
	restart, err := daemon.configureSandbox(controlproto.ConfigureRequest{DevContainers: &enabled})
	if err != nil {
		t.Fatal(err)
	}
	if !restart {
		t.Fatal("enabling the second OCI root did not require restart")
	}
	if br.devContainers.Load() {
		t.Fatal("running broker switched to an IDE root that is not attached")
	}
	persisted := store.Snapshot()
	if !persisted.DevContainers || persisted.DevContainersImage != ideImage ||
		persisted.DevContainersRWLayer != ideLayer || persisted.DevContainersImageCfg == nil {
		t.Fatalf("prepared Dev Containers profile was not persisted: %+v", persisted)
	}
}

func TestConfigureDevContainersPreflightFailureDoesNotPersist(t *testing.T) {
	dir := t.TempDir()
	initial := config.RunConfig{SSH: true, Runtime: "crun", MemMB: 512, VCPUs: 1}
	data, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	oldEnsureImage := ensureDevContainersImageAsset
	t.Cleanup(func() { ensureDevContainersImageAsset = oldEnsureImage })
	wantErr := errors.New("curated image unavailable")
	ensureDevContainersImageAsset = func(string, func(string, ...any)) (string, error) { return "", wantErr }

	enabled := true
	daemon := &daemonRuntime{name: "dev", store: store, broker: &broker{}}
	restart, err := daemon.configureSandbox(controlproto.ConfigureRequest{DevContainers: &enabled})
	if restart || !errors.Is(err, wantErr) {
		t.Fatalf("configure result = restart %t, err %v; want preflight failure", restart, err)
	}
	persisted := store.Snapshot()
	if persisted.DevContainers || persisted.DevContainersImage != "" || persisted.DevContainersRWLayer != "" {
		t.Fatalf("failed preflight persisted unusable profile: %+v", persisted)
	}
}

func TestConfigureAppliesLiveStateAfterCommittedDurabilityError(t *testing.T) {
	dir := t.TempDir()
	initial := config.RunConfig{SSH: true, Runtime: "crun", MemMB: 512, VCPUs: 1}
	data, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "sandbox.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("directory sync failed")
	store.SetWriter(func(path string, data []byte, mode os.FileMode) error {
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
		return &atomicfile.CommitError{Err: wantErr}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	daemon := &daemonRuntime{
		dir: dir, store: store, broker: &broker{}, sshListener: listener,
	}
	restart, err := daemon.configureSandbox(controlproto.ConfigureRequest{SSH: &disabled})
	if restart || !atomicfile.Committed(err) || !errors.Is(err, wantErr) {
		t.Fatalf("configure result = restart %t, err %v; want committed durability error", restart, err)
	}
	if daemon.sshListener != nil {
		t.Fatal("committed SSH disable returned before stopping the live gateway")
	}
	if got := store.Snapshot(); got.SSH {
		t.Fatalf("in-memory SSH setting = %t, want false", got.SSH)
	}
	persisted, readErr := config.ReadSandboxConfig(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if persisted.SSH {
		t.Fatal("committed on-disk SSH setting remained enabled")
	}
}

func TestConfigurePersistsRuntimeNormalizationOnOtherwiseNoopUpdate(t *testing.T) {
	dir := t.TempDir()
	initial := config.RunConfig{
		SSH: true, DevContainers: true, RW: true,
		RWLayer: filepath.Join(dir, "rw.ext4"), MemMB: 4096, VCPUs: 2,
	}
	data, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := config.LoadConfigStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	daemon := &daemonRuntime{store: store, broker: &broker{}}
	restart, err := daemon.configureSandbox(controlproto.ConfigureRequest{
		SSH: &enabled, DevContainers: &enabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restart {
		t.Fatal("runtime normalization unexpectedly requires VM restart")
	}
	persisted, err := config.ReadSandboxConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Runtime != "crun" {
		t.Fatalf("persisted runtime = %q, want crun", persisted.Runtime)
	}
}
