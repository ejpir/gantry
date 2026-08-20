package client

import (
	"strings"
	"testing"
)

// The rootfs spike reuses the fake guest from spike_test.go; the checker
// binary's argv (/spikecheck ...) is scripted there as a clean exit.

func newRootfsSpikeTestOptions() RootfsSpikeOptions {
	return RootfsSpikeOptions{
		ExportTag:    "mcrootfs",
		ROTag:        "mcrootfs-ro",
		WhiteoutPath: "/etc/alpine-release",
	}
}

func TestRootfsSpikeHappyPath(t *testing.T) {
	var report strings.Builder
	guest := newFakeGuest(&report)
	result, err := guest.spike.runRootfsSpike(newRootfsSpikeTestOptions())
	if err != nil {
		t.Fatalf("runRootfsSpike: %v\ntranscript:\n%s", err, report.String())
	}
	if guest.spike.passed != guest.spike.steps {
		t.Fatalf("passed %d of %d steps\ntranscript:\n%s", guest.spike.passed, guest.spike.steps, report.String())
	}
	if result.RWStatus != 0 || result.ROStatus != 0 {
		t.Errorf("checker statuses rw=%d ro=%d, want 0/0", result.RWStatus, result.ROStatus)
	}

	// The hub was mounted guest-side before any task ran.
	specs := guest.mounts.specs()
	if len(specs) == 0 || specs[0].Type != "virtiofs" || specs[0].Target != HubVMPathForTest {
		t.Fatalf("guest hub mount missing or wrong: %+v", specs)
	}

	// Both rootfs tasks bind-mounted their export as the bundle rootfs.
	for id, want := range map[string]string{"mc-rw": "mcrootfs", "mc-ro": "mcrootfs-ro"} {
		chain := guest.tasks.rootfs[id]
		if len(chain) != 1 || chain[0].Type != "bind" {
			t.Fatalf("%s rootfs chain = %+v, want a single bind", id, chain)
		}
		if !strings.HasSuffix(chain[0].Source, "/"+want) {
			t.Errorf("%s rootfs source %q, want .../%s", id, chain[0].Source, want)
		}
	}
	if len(guest.spike.owned) != 0 {
		t.Errorf("spike still owns tasks after cleanup: %v", guest.spike.owned)
	}
}

func TestRootfsSpikeDetectsCheckerFailure(t *testing.T) {
	var report strings.Builder
	guest := newFakeGuest(&report)
	guest.tasks.evilExit = true
	_, err := guest.spike.runRootfsSpike(newRootfsSpikeTestOptions())
	if err == nil {
		t.Fatalf("runRootfsSpike succeeded with a failing checker:\n%s", report.String())
	}
	if !strings.Contains(err.Error(), "exit status") {
		t.Errorf("error %v does not name the checker failure", err)
	}
	if !strings.Contains(report.String(), "FAIL export bind-mounted as bundle rootfs") {
		t.Errorf("transcript does not record the failing step:\n%s", report.String())
	}
	// Independent scenarios still ran after the rw failure: the RO and perf
	// tasks were attempted, and only the hub-mount assertion passed.
	if guest.tasks.rootfs["mc-ro"] == nil || guest.tasks.rootfs["mc-perf"] == nil {
		t.Error("an rw-battery failure hid the independent ro/perf scenarios")
	}
	if guest.spike.passed != 1 {
		t.Errorf("passed %d steps, want exactly the structural hub mount", guest.spike.passed)
	}
}

func TestRootfsTaskConfigKeepsRootWritable(t *testing.T) {
	config, err := rootfsTaskConfig([]string{"/spikecheck"})
	if err != nil {
		t.Fatal(err)
	}
	// Even the RO-export task renders root.readonly=false: a rejected write
	// must then be attributable to host-side export enforcement alone.
	if strings.Contains(config, `"readonly":true`) {
		t.Error("rootfs task config sets root.readonly; host enforcement would be untestable")
	}
	if !strings.Contains(config, `"path":"rootfs"`) {
		t.Error("rootfs task config does not target the bundle rootfs")
	}
	for _, ns := range []string{`"type":"pid"`, `"type":"mount"`, `"type":"ipc"`, `"type":"uts"`} {
		if !strings.Contains(config, ns) {
			t.Errorf("config missing namespace %s", ns)
		}
	}
}

func TestHubBindRootfs(t *testing.T) {
	mounts := hubBindRootfs("/run/mnt/gantry-shares/mcrootfs")
	if len(mounts) != 1 {
		t.Fatalf("got %d mounts, want 1", len(mounts))
	}
	mount := mounts[0]
	if mount.Type != "bind" || mount.Source != "/run/mnt/gantry-shares/mcrootfs" {
		t.Errorf("unexpected mount: %+v", mount)
	}
	rbind := false
	for _, option := range mount.Options {
		if option == "rbind" {
			rbind = true
		}
	}
	if !rbind {
		t.Errorf("bind mount missing rbind: %+v", mount.Options)
	}
}

// HubVMPathForTest keeps the assertion independent of the shares constant's
// exact value.
const HubVMPathForTest = "/run/mnt/gantry-shares"
