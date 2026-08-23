package client

// layerset.go — native multi-device EROFS image sets.
//
// Gantry's default image path flattens an OCI image into a single EROFS
// attached as /dev/vdb. The containerd erofs snapshotter instead keeps
// each layer as its own EROFS blob plus one metadata-only "fsmeta" EROFS
// that merges them, and the guest mounts the fsmeta device with every
// layer blob as an extra `device=` mount option (multi-device EROFS).
// A LayerSet describes such a set so gantry can attach it as-is — e.g.
// pointing straight at another stack's snapshotter store without any
// export/flatten step.

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/containerd/containerd/api/types"
)

// LayerSet is an ordered multi-device EROFS image set. Device order is
// load-bearing: fsmeta references layer blobs by slot index, so Layers
// must stay in exactly the order the composing stack recorded.
type LayerSet struct {
	FSMeta string   `json:"fsmeta"` // metadata erofs (mount source, slot 0)
	Layers []string `json:"layers"` // ordered data-blob erofs devices (slots 1..)
}

// LoadLayerSet reads a layerset manifest ({"fsmeta": ..., "layers": [...]})
// and resolves every path to absolute.
func LoadLayerSet(path string) (*LayerSet, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ls LayerSet
	if err := json.Unmarshal(b, &ls); err != nil {
		return nil, fmt.Errorf("layerset %s: %w", path, err)
	}
	if ls.FSMeta == "" || len(ls.Layers) == 0 {
		return nil, fmt.Errorf("layerset %s: need fsmeta and at least one layer", path)
	}
	abs := func(p string) string {
		if a, err := filepath.Abs(p); err == nil {
			return a
		}
		return p
	}
	ls.FSMeta = abs(ls.FSMeta)
	for i := range ls.Layers {
		ls.Layers[i] = abs(ls.Layers[i])
	}
	return &ls, nil
}

// Validate checks that every file in the set exists.
func (ls LayerSet) Validate() error {
	for _, p := range ls.DisksRO() {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("layerset: %w", err)
		}
	}
	return nil
}

// DisksRO is the virtio-blk attach order (fsmeta first, then layers):
// these become /dev/vdb, /dev/vdc, ... in the guest (vda is the rootfs).
func (ls LayerSet) DisksRO() []string {
	out := make([]string, 0, len(ls.Layers)+1)
	out = append(out, ls.FSMeta)
	return append(out, ls.Layers...)
}

// BlkDevName converts a disk index (0 = vda) to the guest device name,
// following the kernel's virtio-blk lettering (vda..vdz, vdaa...).
func BlkDevName(idx int) string {
	if idx < 0 {
		idx = 0
	}
	if idx < 26 {
		return "/dev/vd" + string(rune('a'+idx))
	}
	return fmt.Sprintf("/dev/vd%c%c", 'a'+idx/26-1, 'a'+idx%26)
}

// FSMetaDev is the guest device for the metadata erofs (always vdb: the
// first disk after the rootfs).
func (ls LayerSet) FSMetaDev() string { return BlkDevName(1) }

// LayerDevs are the guest devices for the data blobs, in slot order.
func (ls LayerSet) LayerDevs() []string {
	out := make([]string, len(ls.Layers))
	for i := range ls.Layers {
		out[i] = BlkDevName(2 + i)
	}
	return out
}

// RWLayerDev is the guest device the writable ext4 layer lands on: right
// after the rootfs + fsmeta + layer blobs.
func (ls LayerSet) RWLayerDev() string { return BlkDevName(2 + len(ls.Layers)) }

// sandboxSessionRootfs bind-mounts the persistent sandbox's assembled
// rootfs into an isolated per-session container. Guest paths stay POSIX on
// every host platform.
func sandboxSessionRootfs(baseID string) []*types.Mount {
	return []*types.Mount{{
		Type:    "bind",
		Source:  path.Join("/run/bundles", baseID, "rootfs"),
		Options: []string{"rbind", "rprivate"},
	}}
}

// RootfsMounts renders the guest rootfs mount chain for the flattened
// single-device image (/dev/vdb, optional rwlayer /dev/vdc).
func RootfsMounts(rw bool) []*types.Mount {
	return rootfsMountsDevs(rw, "/dev/vdb", nil, "/dev/vdc")
}

// RootfsMountsLayerSet renders the chain for a multi-device EROFS set:
// mount 0 is the fsmeta device with every layer blob as a device= option,
// mount 1 is the rwlayer, and the overlay stacks upper/work over it —
// the exact compose the containerd erofs snapshotter records.
func RootfsMountsLayerSet(ls LayerSet) []*types.Mount {
	return rootfsMountsDevs(true, ls.FSMetaDev(), ls.LayerDevs(), ls.RWLayerDev())
}

// rootfsMountsDevs builds the mount chain. layerDevs nil selects the
// flattened single-device image at imageDev.
func rootfsMountsDevs(rw bool, imageDev string, layerDevs []string, rwDev string) []*types.Mount {
	erofsOpts := []string{"ro"}
	for _, d := range layerDevs {
		erofsOpts = append(erofsOpts, "device="+d)
	}
	if !rw {
		return []*types.Mount{{Type: "erofs", Source: imageDev, Options: erofsOpts}}
	}
	return []*types.Mount{
		{Type: "erofs", Source: imageDev, Options: erofsOpts},
		{Type: "ext4", Source: rwDev, Options: []string{"rw"}},
		{Type: "format/overlay", Source: "overlay", Options: []string{
			"lowerdir={{mount 0}}",
			"upperdir={{mount 1}}/upper",
			"workdir={{mount 1}}/work",
			// The nerdbox arm64 kernel builds with
			// CONFIG_OVERLAY_FS_INDEX=y, which makes "index" default
			// ON for every overlay mount — and index's origin
			// verification (exportfs fh decode of the upper root)
			// fails the whole mount with ESTALE when the rwlayer is
			// damaged or carries xattrs from a previous image pairing.
			// We need neither the inode index nor NFS export; pin
			// both index and xino off explicitly (x86_64 kernels
			// default them off already). gVisor's sentry ignores
			// unknown overlay options, so runsc is unaffected.
			"index=off",
			"xino=off",
		}},
	}
}
