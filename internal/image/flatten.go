package image

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	erofs "github.com/erofs/go-erofs"
)

// flatten.go — merge OCI layer tars into one erofs.Writer with aufs
// whiteout semantics (design doc: "Build pipeline / Flattening").
//
// Layers are decompressed tar FILES on disk, so a two-pass index gives
// us: whiteouts applied to the accumulated set, last-writer-wins per
// path, first-seen emission order, and hardlinks materialized by reading
// the target's data back by offset (alpine's /bin/* are all hardlinks to
// busybox — skipping this silently breaks real images). Only headers are
// held resident; file bodies stream from the layer files, so peak memory
// is proportional to the entry count, not the image size.

// loc points at one tar entry's data inside a decompressed layer file.
type loc struct {
	layer int
	off   int64 // data offset within the layer file
	size  int64
	hdr   tar.Header
}

// mergeIndex is the accumulated path → loc map plus emission order.
type mergeIndex struct {
	entries map[string]*loc
	order   []string // first-seen order; may hold stale paths (skipped at emit)
}

const (
	whPrefix = ".wh."
	whOpaque = ".wh..wh..opq"
)

// cleanTarName normalizes a tar entry name to an absolute-path form
// without a leading slash ("etc/passwd"), rejecting traversal. The
// flatten never writes files by name to disk, but the erofs writer is
// not our code — reject ".." before it reaches the output stream.
func cleanTarName(name string) (string, error) {
	name = strings.TrimPrefix(name, "/")
	p := path.Clean(name)
	if p == "." || p == "/" {
		return "", nil // the root entry itself
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("tar entry %q escapes the root", name)
	}
	return p, nil
}

// indexLayers scans every layer and builds the merged index.
func indexLayers(layers []*os.File) (*mergeIndex, error) {
	idx := &mergeIndex{entries: map[string]*loc{}}
	for i, f := range layers {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		tr := tar.NewReader(f)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("layer %d: %w", i, err)
			}
			name, err := cleanTarName(hdr.Name)
			if err != nil {
				return nil, fmt.Errorf("layer %d: %w", i, err)
			}
			if name == "" {
				continue // root; we always synthesize our own
			}
			// data starts at the current read offset (tar.Reader has
			// consumed exactly the header)
			dataOff, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return nil, err
			}
			base := path.Base(name)
			if strings.HasPrefix(base, whPrefix) {
				if base == whOpaque {
					// opaque dir: clear strictly-below; the directory's
					// own entry (mode/owner) survives
					idx.removeBelow(path.Dir(name))
				} else {
					// plain whiteout: remove the victim AND, when it is
					// a directory, everything beneath it — a layer that
					// rm -rf's a tree must not leave the children live
					idx.removeAtOrBelow(path.Join(path.Dir(name), base[len(whPrefix):]))
				}
				continue
			}
			if _, seen := idx.entries[name]; !seen {
				idx.order = append(idx.order, name)
			}
			h := *hdr
			idx.entries[name] = &loc{layer: i, off: dataOff, size: hdr.Size, hdr: h}
		}
	}
	return idx, nil
}

// removeBelow drops accumulated entries strictly beneath dir (opaque
// dir marker): the directory entry itself keeps its mode/ownership.
func (idx *mergeIndex) removeBelow(dir string) {
	for p := range idx.entries {
		if strings.HasPrefix(p, dir+"/") {
			delete(idx.entries, p)
		}
	}
}

// removeAtOrBelow drops victim and everything beneath it (plain
// whiteout). removeBelow is not enough here: a deleted directory's
// children must not survive into the flattened image — image authors
// rely on the deletion to remove build tooling and credentials.
func (idx *mergeIndex) removeAtOrBelow(victim string) {
	for p := range idx.entries {
		if p == victim || strings.HasPrefix(p, victim+"/") {
			delete(idx.entries, p)
		}
	}
}

// readFile returns the content of a regular file in the merged set
// (used for /etc/passwd + /etc/group at build time, and in tests).
func (idx *mergeIndex) readFile(layers []*os.File, name string) ([]byte, error) {
	l, ok := idx.entries[name]
	if !ok || l.hdr.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("%s: not a regular file in the merged image", name)
	}
	out := make([]byte, l.size)
	_, err := layers[l.layer].ReadAt(out, l.off)
	return out, err
}

// unixMknodMode maps a tar typeflag to erofs mknod type bits (standard
// Unix values; internal/disk in go-erofs is not importable).
func unixMknodMode(tf byte, perm uint32) (uint16, bool) {
	const (
		tFifo = 0o010000
		tChr  = 0o020000
		tBlk  = 0o060000
		tSock = 0o140000
	)
	switch tf {
	case tar.TypeFifo:
		return tFifo | uint16(perm&0o7777), true
	case tar.TypeChar:
		return tChr | uint16(perm&0o7777), true
	case tar.TypeBlock:
		return tBlk | uint16(perm&0o7777), true
	case 's': // GNU/USTAR socket (archive/tar has no constant)
		return tSock | uint16(perm&0o7777), true
	}
	return 0, false
}

// linuxRdev encodes device numbers the way Linux does (new_encode_dev).
func linuxRdev(major, minor int64) uint32 {
	return uint32(major&0xfff)<<8 | uint32(minor&0xff) | uint32(minor&^0xff)<<12
}

// goFileMode converts a tar mode (unix bits incl. setuid/sticky) to
// fs.FileMode so go-erofs' Chmod keeps the high bits.
func goFileMode(perm int64) fs.FileMode {
	m := fs.FileMode(perm & 0o777).Perm()
	if perm&0o4000 != 0 {
		m |= fs.ModeSetuid
	}
	if perm&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	if perm&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	return m
}

type layerEmitter struct {
	writer         *erofs.Writer
	layers         []*os.File
	index          *mergeIndex
	hardlinkMisses int
}

func (e *layerEmitter) emit(name string, entry *loc) error {
	header := &entry.hdr
	outputPath := "/" + name
	switch header.Typeflag {
	case tar.TypeDir:
		if err := e.writer.Mkdir(outputPath, 0o755); err != nil {
			return err
		}
		if err := e.writer.Chmod(outputPath, goFileMode(header.Mode)); err != nil {
			return err
		}
	case tar.TypeReg:
		if err := e.emitRegular(outputPath, name, entry, header.Mode); err != nil {
			return err
		}
	case tar.TypeSymlink:
		if err := e.writer.Symlink(header.Linkname, outputPath); err != nil {
			return err
		}
	case tar.TypeLink:
		emitted, err := e.emitHardlink(outputPath, name, header)
		if err != nil {
			return err
		}
		if !emitted {
			return nil
		}
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo, 's':
		mode, ok := unixMknodMode(header.Typeflag, uint32(header.Mode))
		if !ok {
			return nil
		}
		if err := e.writer.Mknod(outputPath, mode, linuxRdev(header.Devmajor, header.Devminor)); err != nil {
			return err
		}
	default:
		return nil
	}
	return e.setMetadata(outputPath, header)
}

func (e *layerEmitter) emitRegular(outputPath, name string, entry *loc, mode int64) error {
	file, err := e.writer.Create(outputPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, io.NewSectionReader(e.layers[entry.layer], entry.off, entry.size)); err != nil {
		_ = file.Close()
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := file.Chmod(goFileMode(mode)); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (e *layerEmitter) emitHardlink(outputPath, name string, header *tar.Header) (bool, error) {
	targetName, err := cleanTarName(header.Linkname)
	if err != nil {
		return false, err
	}
	target, ok := e.index.entries[targetName]
	if !ok || target.hdr.Typeflag != tar.TypeReg {
		e.hardlinkMisses++
		return false, nil
	}
	return true, e.emitRegular(outputPath, name, target, header.Mode)
}

func (e *layerEmitter) setMetadata(outputPath string, header *tar.Header) error {
	if err := e.writer.Chown(outputPath, header.Uid, header.Gid); err != nil {
		return err
	}
	modified := header.ModTime
	if modified.IsZero() {
		modified = time.Unix(0, 0)
	}
	if err := e.writer.Chtimes(outputPath, modified, modified); err != nil {
		return err
	}
	for key, value := range header.PAXRecords {
		attribute, ok := strings.CutPrefix(key, "SCHILY.xattr.")
		if ok {
			if err := e.writer.Setxattr(outputPath, attribute, value); err != nil {
				return err
			}
		}
	}
	return nil
}

type orderedPath struct {
	name  string
	depth int
}

func (idx *mergeIndex) livePathsByDepth() []orderedPath {
	paths := make([]orderedPath, 0, len(idx.entries))
	seen := make(map[string]struct{}, len(idx.entries))
	for _, name := range idx.order {
		if _, live := idx.entries[name]; !live {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		paths = append(paths, orderedPath{name: name, depth: strings.Count(name, "/")})
	}
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].depth < paths[j].depth })
	return paths
}

// flattenLayers merges layers into w. Returns the index (the caller
// reads /etc/passwd + /etc/group from it for image-user resolution).
func flattenLayers(w *erofs.Writer, layers []*os.File, logf func(string, ...any)) (*mergeIndex, error) {
	idx, err := indexLayers(layers)
	if err != nil {
		return nil, err
	}

	// An explicit root first: without it the root directory inherits the
	// builder's uid (the mkfs.erofs --tar gotcha from the design spike —
	// same failure mode applies to any builder).
	if err := w.Mkdir("/", 0o755); err != nil {
		return nil, err
	}
	if err := w.Chown("/", 0, 0); err != nil {
		return nil, err
	}

	// Emit in depth order (parents before children, first-seen order
	// within a depth): the writer's ensureParent auto-creates missing
	// parents (root-owned 0755, at most once), and checkPath ERRORS on
	// duplicate paths — so every explicit directory must be created
	// before any entry beneath it, or a later explicit Mkdir on an
	// auto-created parent would fail with "duplicate path".
	// paths are deduplicated before sorting, avoiding both the old O(n^2)
	// exchange sort and a second full path-keyed map.
	emitter := layerEmitter{writer: w, layers: layers, index: idx}
	for _, path := range idx.livePathsByDepth() {
		if err := emitter.emit(path.name, idx.entries[path.name]); err != nil {
			return nil, err
		}
	}
	if emitter.hardlinkMisses > 0 && logf != nil {
		logf("flatten: %d hardlink(s) with unresolvable targets skipped", emitter.hardlinkMisses)
	}
	return idx, nil
}
