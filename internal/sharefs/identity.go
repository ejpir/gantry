package sharefs

import (
	"fmt"
	"path/filepath"
	"runtime"
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
	path string
	// scope is a namespace-independent path within volume. Linux derives it
	// from /proc/self/mountinfo, whose mount-root field preserves the source
	// location of bind mounts. It lets overlap checks recognize an aliased
	// ancestor or descendant even when path is lexically unrelated.
	scope      string
	scopeValid bool
	// mountedScopes identifies filesystems reachable through mount points
	// below path. Linux records these while the root is pinned so an export
	// cannot hide a protected directory beneath an otherwise unrelated tree.
	mountedScopes []identityScope
	filesystem    string
	volume        uint64
	object        uint64
	valid         bool
	objectID      bool
	caseFold      bool
}

type identityScope struct {
	path       string
	volume     uint64
	filesystem string
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

// ValidateExport rejects kernel-control filesystems whose apparent regular
// files are privileged host APIs rather than ordinary storage. The check also
// covers mounts nested below an otherwise safe share root.
func (i Identity) ValidateExport() error {
	if !i.valid {
		return fmt.Errorf("invalid share identity")
	}
	if runtime.GOOS == "darwin" && identityPathContains(i.path, "/System/Volumes/Data", true) {
		// The Data volume is nested below the sealed System volume but its
		// firmlink descendants appear at paths such as /Users. Without a full
		// Darwin mount-scope inventory, exporting Data or one of its namespace
		// ancestors would hide those descendants from ordinary containment
		// checks. Narrow roots below the firmlink remain supported.
		return fmt.Errorf("share root %s contains the macOS Data-volume firmlink root; choose a narrower directory", i.path)
	}
	if restrictedExportFilesystem(i.filesystem) {
		return fmt.Errorf("share root %s uses restricted host filesystem %s", i.path, i.filesystem)
	}
	for _, mounted := range i.mountedScopes {
		if restrictedExportFilesystem(mounted.filesystem) {
			return fmt.Errorf("share root %s contains restricted host filesystem %s", i.path, mounted.filesystem)
		}
	}
	return nil
}

func restrictedExportFilesystem(filesystem string) bool {
	switch filesystem {
	case "apparmorfs", "autofs", "binder", "binderfs", "binfmt_misc", "bpf",
		"cgroup", "cgroup2", "configfs", "debugfs", "devfs", "devpts", "devtmpfs",
		"dlmfs", "efivarfs", "functionfs", "fusectl", "gadgetfs", "gfs2meta",
		"mqueue", "nfsd", "nsfs", "ocfs2_dlmfs", "openpromfs", "proc",
		"pstore", "resctrl", "rpc_pipefs", "securityfs", "selinuxfs",
		"smackfs", "sysfs", "tracefs", "usbdevfs", "usbfs", "xenfs", "zonefs":
		return true
	default:
		return false
	}
}

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
	if i.scopeValid && other.scopeValid {
		fold := i.caseFold && other.caseFold
		left := append([]identityScope{{path: i.scope, volume: i.volume}}, i.mountedScopes...)
		right := append([]identityScope{{path: other.scope, volume: other.volume}}, other.mountedScopes...)
		for _, a := range left {
			for _, b := range right {
				if a.volume == b.volume && identityPathsOverlap(a.path, b.path, fold) {
					return true
				}
			}
		}
	}
	return identityPathsOverlap(i.path, other.path, i.caseFold && other.caseFold)
}

// Contains reports whether other names the same directory or a directory
// below i. Unlike Overlaps it is directional, which lets policy code decide
// whether a sensitive path is reachable through an exported root without
// treating the sensitive path's unrelated parent as part of the export.
func (i Identity) Contains(other Identity) bool {
	if i.Aliases(other) {
		return true
	}
	if !i.valid || !other.valid {
		return false
	}
	if i.scopeValid && other.scopeValid {
		fold := i.caseFold && other.caseFold
		parents := append([]identityScope{{path: i.scope, volume: i.volume}}, i.mountedScopes...)
		for _, parent := range parents {
			if parent.volume == other.volume && identityPathContains(parent.path, other.scope, fold) {
				return true
			}
		}
	}
	return identityPathContains(i.path, other.path, i.caseFold && other.caseFold)
}

func identityPathsOverlap(a, b string, fold bool) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	return pathEqual(a, b, fold) || pathChildOf(a, b, fold) || pathChildOf(b, a, fold)
}

func identityPathContains(parent, child string, fold bool) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	return pathEqual(parent, child, fold) || pathChildOf(child, parent, fold)
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
