package config

import (
	"path"
	"strings"

	"github.com/ejpir/gantry/internal/shares"
)

// MaxManagedShares caps the persisted share set. The live hub enforces the
// same bound; keeping the constant here lets ConfigStore reject an overflowing
// restart configuration without reaching into the control plane.
const MaxManagedShares = 256

// DefaultHubCtrPath is the implicit container target for a tag mounted
// through the persistent hub.
func DefaultHubCtrPath(tag string) string { return shares.HubHostPath + "/" + tag }

// ContainerPathsOverlap is pathsOverlap for guest container paths: always
// slash-separated regardless of the host OS, so it must not go through
// filepath.Clean on Windows. Equal, ancestor, and descendant targets all
// overlap — a bind-mount at any of those shadows (or is shadowed by) the
// hub FUSE mount depending on mount order.
func ContainerPathsOverlap(a, b string) bool {
	a = path.Clean(a)
	b = path.Clean(b)
	if a == b || a == "/" || b == "/" {
		// the root contains every target
		return true
	}
	return strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// ConfiguredShareTarget is the container path a share resolves to, explicit
// or derived.
func ConfiguredShareTarget(share shares.Spec) string {
	if share.CtrPath != "" {
		return share.CtrPath
	}
	return DefaultHubCtrPath(share.Tag)
}

// ShareConfigSpec renders a share for sandbox.json.
func ShareConfigSpec(share shares.Spec) string {
	// The persistent hub's implicit target is /host/<tag>. Keep omitting that
	// derived value from sandbox.json while delegating canonical formatting to
	// the share model.
	if share.CtrPath == DefaultHubCtrPath(share.Tag) {
		share.CtrPath = ""
	}
	return share.String()
}

// ShareSpecsReplacingTag returns specs with every entry for tag dropped and
// newSpec appended ("" = removal only). One slice, one write — replacing a
// share never takes the remove-then-add path that a crash could split.
func ShareSpecsReplacingTag(specs []string, tag, newSpec string) []string {
	out := make([]string, 0, len(specs)+1)
	for _, raw := range specs {
		share, err := shares.ParseSpec(raw)
		if err != nil || share.Tag != tag {
			out = append(out, raw)
		}
	}
	if newSpec != "" {
		out = append(out, newSpec)
	}
	return out
}
