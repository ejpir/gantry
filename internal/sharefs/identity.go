package sharefs

import (
	"path/filepath"
	"strings"
)

// Identity describes the directory actually pinned by a share export. Path is
// resolved from the open descriptor or handle; volume and object identify the
// directory independently of its name. Keeping both lets the control plane
// reject ordinary ancestor overlap as well as aliases such as bind mounts.
//
// The fields are intentionally private. Identities are constructed only from
// open kernel objects, so callers cannot accidentally turn an unchecked path
// string into a trusted identity.
type Identity struct {
	path     string
	volume   uint64
	object   uint64
	valid    bool
	objectID bool
	caseFold bool
}

func newIdentity(path string, volume, object uint64, caseFold bool) Identity {
	return Identity{
		path:     filepath.Clean(path),
		volume:   volume,
		object:   object,
		valid:    true,
		objectID: true,
		caseFold: caseFold,
	}
}

// Path returns the descriptor-derived path retained for persistence and UI.
func (i Identity) Path() string { return i.path }

// Aliases reports whether both identities name the same pinned directory,
// even when the directory is reachable through different host paths.
func (i Identity) Aliases(other Identity) bool {
	return i.valid && other.valid && i.objectID && other.objectID &&
		i.volume == other.volume && i.object == other.object
}

// Overlaps reports whether the roots alias, or one descriptor-derived path is
// an ancestor of the other. The object comparison catches exact bind-mount or
// hard-link aliases that lexical path comparison cannot see.
func (i Identity) Overlaps(other Identity) bool {
	if i.Aliases(other) {
		return true
	}
	if !i.valid || !other.valid {
		return false
	}
	return identityPathsOverlap(i.path, other.path, i.caseFold && other.caseFold)
}

func identityPathsOverlap(a, b string, fold bool) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	return pathEqual(a, b, fold) || pathChildOf(a, b, fold) || pathChildOf(b, a, fold)
}

func pathEqual(a, b string, fold bool) bool {
	if fold {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func pathChildOf(child, parent string, fold bool) bool {
	if parent == "" || len(child) <= len(parent) || !pathEqual(child[:len(parent)], parent, fold) {
		return false
	}
	if parent[len(parent)-1] == byte(filepath.Separator) {
		return true
	}
	return child[len(parent)] == byte(filepath.Separator)
}

// Identify opens path, derives its identity from the opened kernel object,
// and closes it. It is intended for restart-only configuration validation;
// live exports use Prepared.Identity so the same object remains pinned through
// validation and publication.
func Identify(path string) (Identity, error) { return identifyRoot(path) }
