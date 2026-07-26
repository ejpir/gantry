package image

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// source.go — where manifests, configs and layer blobs come from.
// Phase 1 (design doc): local sources only — an OCI layout directory and
// a `docker save` tar. The registry source lands with the auth work.

// pulled is a fetched image ready to build: verified config, platform
// match, and its layers as decompressed tar files (temp dir, caller
// cleans up via Close).
type pulled struct {
	digest string // cache key: manifest digest (oci layout) or derived (docker save)
	ref    string
	config *Config
	layers []*os.File
	tmpDir string
}

// Close releases the decompressed layer temp files.
func (p *pulled) Close() {
	for _, f := range p.layers {
		f.Close()
	}
	if p.tmpDir != "" {
		os.RemoveAll(p.tmpDir)
	}
}

// archToOCI maps the guest-kernel arch names to OCI platform names.
func archToOCI(arch string) string {
	// gantry's vmm.KernelArch returns "arm64" | "amd64", which already
	// match OCI; keep the mapping explicit for future arch names.
	return arch
}

// checkPlatform verifies the image config targets the guest arch.
func checkPlatform(cfg *ociConfig, arch, ref string) error {
	want := archToOCI(arch)
	if cfg.Architecture != "" && cfg.Architecture != want {
		return fmt.Errorf("image %s is linux/%s, but the guest kernel is linux/%s", ref, cfg.Architecture, want)
	}
	if cfg.OS != "" && cfg.OS != "linux" {
		return fmt.Errorf("image %s is for OS %q, need linux", ref, cfg.OS)
	}
	return nil
}

// descriptor is an OCI content descriptor.
type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform"`
}

// ---------------- OCI layout directory ----------------

// loadOCILayout reads an OCI image layout directory (oci-layout +
// index.json + blobs/), selecting the manifest for the guest arch.
func loadOCILayout(dir, ref, arch string) (*pulled, error) {
	idxb, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	var idx struct {
		Manifests []descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(idxb, &idx); err != nil {
		return nil, fmt.Errorf("%s: bad index.json: %w", dir, err)
	}
	if len(idx.Manifests) == 0 {
		return nil, fmt.Errorf("%s: index.json has no manifests", dir)
	}
	// platform match; fall back to the only manifest
	var man *descriptor
	for i := range idx.Manifests {
		m := &idx.Manifests[i]
		if m.Platform != nil && m.Platform.Architecture == archToOCI(arch) &&
			(m.Platform.OS == "" || m.Platform.OS == "linux") {
			man = m
			break
		}
	}
	if man == nil {
		if len(idx.Manifests) == 1 {
			man = &idx.Manifests[0]
		} else {
			return nil, fmt.Errorf("%s: no manifest for linux/%s", dir, archToOCI(arch))
		}
	}
	blobPath := func(digest string) (string, error) {
		algo, hex, ok := strings.Cut(digest, ":")
		if !ok || algo != "sha256" {
			return "", fmt.Errorf("unsupported digest %q", digest)
		}
		return filepath.Join(dir, "blobs", algo, hex), nil
	}
	readBlob := func(d descriptor) ([]byte, error) {
		p, err := blobPath(d.Digest)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		if fmt.Sprintf("sha256:%x", sum) != d.Digest {
			return nil, fmt.Errorf("blob %s: digest mismatch (corrupt store)", d.Digest)
		}
		return b, nil
	}

	manb, err := readBlob(*man)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Config descriptor   `json:"config"`
		Layers []descriptor `json:"layers"`
	}
	if err := json.Unmarshal(manb, &manifest); err != nil {
		return nil, fmt.Errorf("bad manifest: %w", err)
	}
	cfgb, err := readBlob(manifest.Config)
	if err != nil {
		return nil, err
	}
	var oc ociConfig
	if err := json.Unmarshal(cfgb, &oc); err != nil {
		return nil, fmt.Errorf("bad image config: %w", err)
	}
	if err := checkPlatform(&oc, arch, ref); err != nil {
		return nil, err
	}

	p := &pulled{digest: man.Digest, ref: ref, tmpDir: ""}
	tmp, err := os.MkdirTemp("", "gantry-image-")
	if err != nil {
		return nil, err
	}
	p.tmpDir = tmp
	for i, l := range manifest.Layers {
		bp, err := blobPath(l.Digest)
		if err != nil {
			p.Close()
			return nil, err
		}
		f, err := decompressTo(bp, l.Digest, tmp, i)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.layers = append(p.layers, f)
	}
	p.config = &Config{
		Env:        oc.Config.Env,
		Entrypoint: oc.Config.Entrypoint,
		Cmd:        oc.Config.Cmd,
		User:       oc.Config.User,
		WorkingDir: oc.Config.WorkingDir,
	}
	return p, nil
}

// ---------------- docker save tar ----------------

// loadDockerSave reads a `docker save` tar: manifest.json naming a
// config blob and layer tars. The cache key is derived (docker save
// carries no manifest digest): sha256 over config + ordered layer ids.
func loadDockerSave(tarPath, ref, arch string) (*pulled, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tmp, err := os.MkdirTemp("", "gantry-image-")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*pulled, error) {
		os.RemoveAll(tmp)
		return nil, err
	}

	type manEntry struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	var mans []manEntry
	layerBlobs := map[string]string{} // tar member -> extracted path
	var configPath string

	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(fmt.Errorf("read %s: %w", tarPath, err))
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		switch {
		case name == "manifest.json":
			b, err := io.ReadAll(tr)
			if err != nil {
				return fail(err)
			}
			if err := json.Unmarshal(b, &mans); err != nil {
				return fail(fmt.Errorf("bad manifest.json: %w", err))
			}
		case strings.HasSuffix(name, ".json") && !strings.Contains(name, "/"):
			// the config blob is a top-level <digest>.json
			dst := filepath.Join(tmp, "config.json")
			if err := extractTo(tr, dst); err != nil {
				return fail(err)
			}
			configPath = dst
		default:
			// <id>/layer.tar members
			if strings.HasSuffix(name, "/layer.tar") {
				dst := filepath.Join(tmp, fmt.Sprintf("layer-%d.tar", len(layerBlobs)))
				if err := extractTo(tr, dst); err != nil {
					return fail(err)
				}
				layerBlobs[name] = dst
			}
		}
	}
	if len(mans) == 0 {
		return fail(fmt.Errorf("%s: no manifest.json (not a docker save tar?)", tarPath))
	}
	m := mans[0]

	var cfgData []byte
	if configPath != "" && m.Config != "" {
		cfgData, _ = os.ReadFile(configPath)
	}
	var oc ociConfig
	if len(cfgData) > 0 {
		if err := json.Unmarshal(cfgData, &oc); err != nil {
			return fail(fmt.Errorf("bad image config: %w", err))
		}
	}
	if err := checkPlatform(&oc, arch, ref); err != nil {
		return fail(err)
	}

	p := &pulled{ref: ref, tmpDir: tmp}
	h := sha256.New()
	h.Write(cfgData)
	for _, lname := range m.Layers {
		lp, ok := layerBlobs[lname]
		if !ok {
			p.Close()
			return nil, fmt.Errorf("manifest.json names %s but it is not in the tar", lname)
		}
		f, err := os.Open(lp)
		if err != nil {
			p.Close()
			return nil, err
		}
		p.layers = append(p.layers, f)
		lh := sha256.New()
		if _, err := io.Copy(lh, f); err != nil {
			p.Close()
			return nil, err
		}
		fmt.Fprintf(h, "\n%x", lh.Sum(nil))
	}
	p.digest = fmt.Sprintf("sha256:%x", h.Sum(nil))
	p.config = &Config{
		Env:        oc.Config.Env,
		Entrypoint: oc.Config.Entrypoint,
		Cmd:        oc.Config.Cmd,
		User:       oc.Config.User,
		WorkingDir: oc.Config.WorkingDir,
	}
	return p, nil
}

// extractTo writes the current tar member to dst.
func extractTo(r io.Reader, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, r)
	return err
}

// decompressTo writes src (a tar or tar.gz blob) to tmp as a plain tar,
// verifying the sha256 against wantDigest ("sha256:...") when given.
func decompressTo(src, wantDigest, tmp string, idx int) (*os.File, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dst := filepath.Join(tmp, fmt.Sprintf("layer-%d.tar", idx))
	out, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	r := io.TeeReader(f, h)
	// sniff gzip (OCI layers are usually gzip; docker save never is)
	var magic [2]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		out.Close()
		return nil, err
	}
	r = io.MultiReader(readahead(magic[:]), r)
	var plain io.Reader = r
	if magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			out.Close()
			return nil, err
		}
		defer gz.Close()
		plain = gz
	}
	if _, err := io.Copy(out, plain); err != nil {
		out.Close()
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	if wantDigest != "" {
		if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != wantDigest {
			os.Remove(dst)
			return nil, fmt.Errorf("layer blob %s: digest mismatch (got %s)", src, got)
		}
	}
	return os.Open(dst)
}

// readahead returns a reader over an already-consumed prefix.
func readahead(b []byte) io.Reader { return strings.NewReader(string(b)) }
