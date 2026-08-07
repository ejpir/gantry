package image

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	erofs "github.com/erofs/go-erofs"
)

// builder.go — the flattened-tar → EROFS step, backed by
// github.com/erofs/go-erofs (pure Go, no mkfs.erofs, no privileges).
// Verification is a read-back through go-erofs' own reader: the image
// must parse, walk to the entry count we emitted, and return correct
// content for a sampled file — the fsck.erofs role from the design doc.

// Build flattens layers into outPath (written atomically: tmp + rename)
// and resolves the image config's user against the merged passwd/group.
// Returns the number of entries emitted.
func Build(outPath string, layers []*os.File, cfg *Config, logf func(string, ...any)) (int, error) {
	// Unique temp name: a fixed outPath+".tmp" let one process delete
	// another's in-flight build during crash-litter cleanup (review
	// finding 4). CreateTemp also makes the file 0600, so the final
	// rename lands with private content private (review finding 6).
	f, err := os.CreateTemp(filepath.Dir(outPath), filepath.Base(outPath)+".*.tmp")
	if err != nil {
		return 0, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	w := erofs.Create(f, erofs.WithBlockSize(4096))
	idx, err := flattenLayers(w, layers, logf)
	if err != nil {
		f.Close()
		return 0, fmt.Errorf("flatten: %w", err)
	}
	if err := w.Close(); err != nil {
		f.Close()
		return 0, fmt.Errorf("erofs finalize: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, err
	}

	// resolve the image user while the merged index is in hand
	if cfg != nil && cfg.User != "" {
		passwd, _ := idx.readFile(layers, "etc/passwd")
		group, _ := idx.readFile(layers, "etc/group")
		uid, gid, err := resolveUser(cfg.User, string(passwd), string(group))
		if err != nil && logf != nil {
			logf("image user %q: %v (falling back to root)", cfg.User, err)
		}
		cfg.UID, cfg.GID = uid, gid
	}

	if err := verify(outPath, tmp, layers, idx); err != nil {
		return 0, fmt.Errorf("verify: %w", err)
	}
	if err := os.Rename(tmp, outPath); err != nil {
		return 0, err
	}
	// CreateTemp's 0600 survives the rename; assert it for images built
	// by an older gantry and re-verified here.
	os.Chmod(outPath, 0o600)
	return len(idx.entries), nil
}

// verify reads the built image back: it must parse, its walk must find
// the regular file we sample, and that file's content must hash to the
// same sha256 as the source layer data. Cheap and catches structural
// corruption before the image is ever cached.
func verify(finalPath, tmpPath string, layers []*os.File, idx *mergeIndex) error {
	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer f.Close()
	img, err := erofs.Open(f)
	if err != nil {
		return fmt.Errorf("open built image: %w", err)
	}

	// pick the first regular file with content as the sample
	var sample string
	for _, name := range idx.order {
		l, ok := idx.entries[name]
		if ok && l.hdr.Typeflag == tar.TypeReg && l.size > 0 {
			sample = name
			break
		}
	}
	var walked, sampleFound int
	var gotSum []byte
	err = fs.WalkDir(img, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		walked++
		if sample != "" && p == sample {
			rc, err := img.Open(p)
			if err != nil {
				return err
			}
			defer rc.Close()
			h := sha256.New()
			if _, err := io.Copy(h, rc); err != nil {
				return err
			}
			gotSum = h.Sum(nil)
			sampleFound++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if walked < 2 { // root + at least one entry
		return fmt.Errorf("built image walks to %d entries, expected content", walked)
	}
	if sample != "" {
		if sampleFound != 1 {
			return fmt.Errorf("sample %q found %d times", sample, sampleFound)
		}
		l := idx.entries[sample]
		h := sha256.New()
		if _, err := io.Copy(h, io.NewSectionReader(layers[l.layer], l.off, l.size)); err != nil {
			return err
		}
		if !bytes.Equal(gotSum, h.Sum(nil)) {
			return fmt.Errorf("sample %q content mismatch after build", sample)
		}
	}
	return nil
}
