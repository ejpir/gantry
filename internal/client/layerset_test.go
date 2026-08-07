package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBlkDevName(t *testing.T) {
	cases := map[int]string{0: "/dev/vda", 1: "/dev/vdb", 25: "/dev/vdz", 26: "/dev/vdaa", 27: "/dev/vdab"}
	for idx, want := range cases {
		if got := BlkDevName(idx); got != want {
			t.Errorf("BlkDevName(%d) = %s, want %s", idx, got, want)
		}
	}
}

func TestLayerSetDevices(t *testing.T) {
	ls := LayerSet{FSMeta: "/s/fsmeta.erofs", Layers: []string{"/s/1.erofs", "/s/2.erofs", "/s/3.erofs"}}
	wantRO := []string{"/s/fsmeta.erofs", "/s/1.erofs", "/s/2.erofs", "/s/3.erofs"}
	got := ls.DisksRO()
	if len(got) != len(wantRO) {
		t.Fatalf("DisksRO = %v", got)
	}
	for i := range wantRO {
		if got[i] != wantRO[i] {
			t.Fatalf("DisksRO[%d] = %s, want %s", i, got[i], wantRO[i])
		}
	}
	if d := ls.FSMetaDev(); d != "/dev/vdb" {
		t.Errorf("FSMetaDev = %s", d)
	}
	devs := ls.LayerDevs()
	for i, want := range []string{"/dev/vdc", "/dev/vdd", "/dev/vde"} {
		if devs[i] != want {
			t.Errorf("LayerDevs[%d] = %s, want %s", i, devs[i], want)
		}
	}
	if d := ls.RWLayerDev(); d != "/dev/vdf" {
		t.Errorf("RWLayerDev = %s", d)
	}
}

func TestRootfsMountsLayerSet(t *testing.T) {
	ls := LayerSet{FSMeta: "/s/fsmeta.erofs", Layers: []string{"/s/1.erofs", "/s/2.erofs"}}
	m := RootfsMountsLayerSet(ls)
	if len(m) != 3 {
		t.Fatalf("want 3 mounts, got %d", len(m))
	}
	if m[0].Type != "erofs" || m[0].Source != "/dev/vdb" {
		t.Fatalf("mount 0: %+v", m[0])
	}
	wantOpts := []string{"ro", "device=/dev/vdc", "device=/dev/vdd"}
	if len(m[0].Options) != len(wantOpts) {
		t.Fatalf("erofs options: %v", m[0].Options)
	}
	for i := range wantOpts {
		if m[0].Options[i] != wantOpts[i] {
			t.Fatalf("erofs option %d: %s, want %s", i, m[0].Options[i], wantOpts[i])
		}
	}
	if m[1].Type != "ext4" || m[1].Source != "/dev/vde" {
		t.Fatalf("mount 1 (rwlayer must follow the two layer blobs): %+v", m[1])
	}
	if m[2].Type != "format/overlay" {
		t.Fatalf("mount 2: %+v", m[2])
	}
	joined := ""
	for _, o := range m[2].Options {
		joined += o + "\n"
	}
	for _, want := range []string{"lowerdir={{mount 0}}", "upperdir={{mount 1}}/upper", "workdir={{mount 1}}/work", "index=off", "xino=off"} {
		if !strings.Contains(joined, want) {
			t.Errorf("overlay options missing %q", want)
		}
	}
}

func TestLoadLayerSet(t *testing.T) {
	dir := t.TempDir()
	fsmeta := filepath.Join(dir, "fsmeta.erofs")
	layer := filepath.Join(dir, "layer.erofs")
	_ = os.WriteFile(fsmeta, []byte("m"), 0o644)
	_ = os.WriteFile(layer, []byte("l"), 0o644)
	manifest := filepath.Join(dir, "ls.json")
	b, _ := json.Marshal(map[string]any{"fsmeta": fsmeta, "layers": []string{layer}})
	_ = os.WriteFile(manifest, b, 0o644)

	ls, err := LoadLayerSet(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if ls.FSMeta != fsmeta || len(ls.Layers) != 1 || ls.Layers[0] != layer {
		t.Fatalf("parsed %+v", ls)
	}
	if err := ls.Validate(); err != nil {
		t.Fatal(err)
	}

	// Missing layer file fails validation.
	b, _ = json.Marshal(map[string]any{"fsmeta": fsmeta, "layers": []string{filepath.Join(dir, "gone.erofs")}})
	_ = os.WriteFile(manifest, b, 0o644)
	ls, err = LoadLayerSet(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := ls.Validate(); err == nil {
		t.Fatal("want validation error for a missing layer")
	}

	// Empty set fails to load.
	b, _ = json.Marshal(map[string]any{"fsmeta": fsmeta})
	_ = os.WriteFile(manifest, b, 0o644)
	if _, err := LoadLayerSet(manifest); err == nil {
		t.Fatal("want load error without layers")
	}
}
