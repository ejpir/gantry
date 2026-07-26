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

	emitted := map[string]bool{}
	var hardlinkMisses int
	emit := func(name string, l *loc) error {
		if emitted[name] {
			return nil
		}
		emitted[name] = true
		hdr := &l.hdr
		p := "/" + name
		setMeta := func() error {
			if err := w.Chown(p, hdr.Uid, hdr.Gid); err != nil {
				return err
			}
			mt := hdr.ModTime
			if mt.IsZero() {
				mt = time.Unix(0, 0)
			}
			if err := w.Chtimes(p, mt, mt); err != nil {
				return err
			}
			for k, v := range hdr.PAXRecords {
				if attr, ok := strings.CutPrefix(k, "SCHILY.xattr."); ok {
					if err := w.Setxattr(p, attr, v); err != nil {
						return err
					}
				}
			}
			return nil
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := w.Mkdir(p, 0o755); err != nil {
				return err
			}
			if err := w.Chmod(p, goFileMode(hdr.Mode)); err != nil {
				return err
			}
			return setMeta()
		case tar.TypeReg:
			f, err := w.Create(p)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.NewSectionReader(layers[l.layer], l.off, l.size)); err != nil {
				f.Close()
				return fmt.Errorf("%s: %w", name, err)
			}
			if err := f.Chmod(goFileMode(hdr.Mode)); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			return setMeta()
		case tar.TypeSymlink:
			if err := w.Symlink(hdr.Linkname, p); err != nil {
				return err
			}
			return setMeta()
		case tar.TypeLink:
			// hardlink: materialize as a copy of the target's data —
			// fs.FS has no hardlink concept and neither does the writer.
			tname, err := cleanTarName(hdr.Linkname)
			if err != nil {
				return err
			}
			tgt, ok := idx.entries[tname]
			if !ok || tgt.hdr.Typeflag != tar.TypeReg {
				hardlinkMisses++
				return nil
			}
			f, err := w.Create(p)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.NewSectionReader(layers[tgt.layer], tgt.off, tgt.size)); err != nil {
				f.Close()
				return err
			}
			if err := f.Chmod(goFileMode(hdr.Mode)); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			return setMeta()
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo, 's':
			mode, ok := unixMknodMode(hdr.Typeflag, uint32(hdr.Mode))
			if !ok {
				return nil
			}
			if err := w.Mknod(p, mode, linuxRdev(hdr.Devmajor, hdr.Devminor)); err != nil {
				return err
			}
			return setMeta()
		default:
			// TypeGNUSparse, TypeXGlobalHeader etc.: nothing to emit
			return nil
		}
	}

	// Emit in depth order (parents before children, first-seen order
	// within a depth): the writer's ensureParent auto-creates missing
	// parents (root-owned 0755, at most once), and checkPath ERRORS on
	// duplicate paths — so every explicit directory must be created
	// before any entry beneath it, or a later explicit Mkdir on an
	// auto-created parent would fail with "duplicate path".
	// parents strictly before children, first-seen order within a depth:
	// stable sort over the insertion order with a precomputed key (the
	// old exchange sort was O(n^2) and unstable — seconds of pure CPU on
	// a 25k-entry image)
	order := append([]string{}, idx.order...)
	depths := make(map[string]int, len(order))
	for _, p := range order {
		depths[p] = strings.Count(p, "/")
	}
	sort.SliceStable(order, func(i, j int) bool { return depths[order[i]] < depths[order[j]] })
	for _, name := range order {
		l, ok := idx.entries[name]
		if !ok {
			continue // shadowed by a later whiteout
		}
		if err := emit(name, l); err != nil {
			return nil, err
		}
	}
	if hardlinkMisses > 0 && logf != nil {
		logf("flatten: %d hardlink(s) with unresolvable targets skipped", hardlinkMisses)
	}
	return idx, nil
}
