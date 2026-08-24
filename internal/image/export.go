package image

// export.go turns Gantry's immutable EROFS lower and optional ext4 overlay
// upper into a portable OCI image-layout archive. Everything is read through
// pure-Go filesystem readers: export needs neither root nor host mounts and
// works on Linux, macOS, and Windows.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/diskfs/go-diskfs/filesystem/ext4"
	"github.com/ejpir/gantry/internal/atomicfile"
	"github.com/ejpir/gantry/internal/ext4view"
	"github.com/ejpir/gantry/internal/gutil"
	erofs "github.com/erofs/go-erofs"
)

const (
	ociImageManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	ociImageIndexMediaType    = "application/vnd.oci.image.index.v1+json"
	ociImageConfigMediaType   = "application/vnd.oci.image.config.v1+json"
	ociLayerGzipMediaType     = "application/vnd.oci.image.layer.v1.tar+gzip"
	ociRefNameAnnotation      = "org.opencontainers.image.ref.name"
)

// ExportOptions describes one stopped sandbox filesystem. Base is either a
// flattened EROFS image or a metadata EROFS whose data devices are Extras.
// RWLayer, when non-nil, is Gantry's locked ext4 disk containing /upper and
// /work. ExportOCI takes ownership of the file and closes it on every path.
type ExportOptions struct {
	Output       string
	Reference    string
	Architecture string
	Base         string
	Extras       []string
	RWLayer      *os.File
	Config       *Config
	Force        bool
	Created      time.Time
	Logf         func(string, ...any)
}

// ExportResult identifies the portable OCI manifest written by ExportOCI.
type ExportResult struct {
	Reference      string
	ManifestDigest string
	Size           int64
}

type exportedLayer struct {
	descriptor descriptor
	diffID     string
	path       string
}

// ExportOCI writes a standard OCI image-layout tar archive atomically. The
// archive contains one complete base layer and, when present, one OCI
// whiteout-aware layer generated from the stopped ext4 upper.
func ExportOCI(options ExportOptions) (*ExportResult, error) {
	if options.RWLayer != nil {
		defer func() { _ = options.RWLayer.Close() }()
	}
	if options.Output == "" {
		return nil, errors.New("OCI export output path is empty")
	}
	if options.Reference == "" {
		return nil, errors.New("OCI export reference is empty")
	}
	if err := validateLocalReference(options.Reference); err != nil {
		return nil, fmt.Errorf("invalid OCI export reference %q: %w", options.Reference, err)
	}
	if options.Architecture != "amd64" && options.Architecture != "arm64" {
		return nil, fmt.Errorf("unsupported OCI export architecture %q", options.Architecture)
	}
	if options.Base == "" {
		return nil, errors.New("OCI export has no EROFS base image")
	}
	if !options.Force {
		if _, err := os.Lstat(options.Output); err == nil {
			return nil, fmt.Errorf("output %s already exists (pass --force to replace it)", options.Output)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect output %s: %w", options.Output, err)
		}
	}

	outputDir := filepath.Dir(options.Output)
	staging, err := os.MkdirTemp(outputDir, ".gantry-export-*")
	if err != nil {
		return nil, fmt.Errorf("create export staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()
	_ = os.Chmod(staging, 0o700)

	say := func(format string, args ...any) {
		if options.Logf != nil {
			options.Logf(format, args...)
		}
	}
	var layers []exportedLayer
	say("exporting immutable base filesystem")
	baseLayer, err := writeLayerBlob(filepath.Join(staging, "base.tar.gz"), "immutable base filesystem", say, func(writer *tar.Writer) error {
		return writeEROFSLayer(writer, options.Base, options.Extras)
	})
	if err != nil {
		return nil, fmt.Errorf("export base filesystem: %w", err)
	}
	layers = append(layers, baseLayer)

	if options.RWLayer != nil {
		say("exporting persistent sandbox changes")
		upperLayer, err := writeLayerBlob(filepath.Join(staging, "upper.tar.gz"), "persistent sandbox changes", say, func(writer *tar.Writer) error {
			return writeExt4UpperLayer(writer, options.RWLayer)
		})
		if err != nil {
			return nil, fmt.Errorf("export writable layer: %w", err)
		}
		layers = append(layers, upperLayer)
	}

	created := options.Created.UTC()
	if created.IsZero() {
		created = time.Now().UTC()
	}
	configBlob, err := marshalExportConfig(created, options.Architecture, options.Config, layers)
	if err != nil {
		return nil, err
	}
	configDesc := descriptorForBytes(ociImageConfigMediaType, configBlob)
	layerDescs := make([]descriptor, len(layers))
	for index := range layers {
		layerDescs[index] = layers[index].descriptor
	}
	manifestBlob, err := json.Marshal(struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Config        descriptor   `json:"config"`
		Layers        []descriptor `json:"layers"`
	}{2, ociImageManifestMediaType, configDesc, layerDescs})
	if err != nil {
		return nil, fmt.Errorf("encode OCI manifest: %w", err)
	}
	manifestDesc := descriptorForBytes(ociImageManifestMediaType, manifestBlob)
	manifestDesc.Platform = &struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	}{Architecture: options.Architecture, OS: "linux"}
	manifestDesc.Annotations = map[string]string{ociRefNameAnnotation: options.Reference}

	indexBlob, err := json.Marshal(struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Manifests     []descriptor `json:"manifests"`
	}{2, ociImageIndexMediaType, []descriptor{manifestDesc}})
	if err != nil {
		return nil, fmt.Errorf("encode OCI index: %w", err)
	}
	layoutBlob := []byte(`{"imageLayoutVersion":"1.0.0"}`)

	say("writing OCI archive %s", options.Output)
	var archivePayloadSize int64
	for _, layer := range layers {
		archivePayloadSize += layer.descriptor.Size
	}
	archiveProgress := newArchiveProgress(archivePayloadSize, say)
	if err := atomicfile.WriteDurable(options.Output, 0o600, func(output io.Writer) error {
		tw := tar.NewWriter(output)
		writeBytes := func(name string, data []byte) error {
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), ModTime: created}); err != nil {
				return err
			}
			_, err := tw.Write(data)
			return err
		}
		writeFile := func(name, source string, size int64) error {
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: size, ModTime: created}); err != nil {
				return err
			}
			file, err := os.Open(source)
			if err != nil {
				return err
			}
			defer func() { _ = file.Close() }()
			written, err := io.CopyN(progressWriter{Writer: tw, Add: archiveProgress.add}, file, size)
			if err != nil {
				return err
			}
			if written != size {
				return fmt.Errorf("short OCI blob copy: wrote %d of %d bytes", written, size)
			}
			return file.Close()
		}
		if err := writeBytes("oci-layout", layoutBlob); err != nil {
			return err
		}
		if err := writeBytes("index.json", indexBlob); err != nil {
			return err
		}
		if err := writeBytes(blobName(configDesc.Digest), configBlob); err != nil {
			return err
		}
		if err := writeBytes(blobName(manifestDesc.Digest), manifestBlob); err != nil {
			return err
		}
		for _, layer := range layers {
			if err := writeFile(blobName(layer.descriptor.Digest), layer.path, layer.descriptor.Size); err != nil {
				return err
			}
		}
		if err := tw.Close(); err != nil {
			return err
		}
		archiveProgress.finish()
		say("syncing OCI archive to disk")
		return nil
	}); err != nil {
		return nil, fmt.Errorf("write OCI archive: %w", err)
	}
	say("finished syncing OCI archive")
	info, err := os.Stat(options.Output)
	if err != nil {
		return nil, fmt.Errorf("stat OCI archive: %w", err)
	}
	return &ExportResult{Reference: options.Reference, ManifestDigest: manifestDesc.Digest, Size: info.Size()}, nil
}

func descriptorForBytes(mediaType string, data []byte) descriptor {
	sum := sha256.Sum256(data)
	return descriptor{MediaType: mediaType, Digest: fmt.Sprintf("sha256:%x", sum), Size: int64(len(data))}
}

func blobName(digest string) string {
	return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func marshalExportConfig(created time.Time, architecture string, config *Config, layers []exportedLayer) ([]byte, error) {
	var exported Config
	if config != nil {
		exported = *config
		exported.Env = append([]string(nil), config.Env...)
		exported.Entrypoint = append([]string(nil), config.Entrypoint...)
		exported.Cmd = append([]string(nil), config.Cmd...)
	}
	diffIDs := make([]string, len(layers))
	for index := range layers {
		diffIDs[index] = layers[index].diffID
	}
	blob, err := json.Marshal(struct {
		Created      string `json:"created"`
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Config       struct {
			Env        []string `json:"Env,omitempty"`
			Entrypoint []string `json:"Entrypoint,omitempty"`
			Cmd        []string `json:"Cmd,omitempty"`
			User       string   `json:"User,omitempty"`
			WorkingDir string   `json:"WorkingDir,omitempty"`
		} `json:"config"`
		RootFS struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}{
		Created:      created.Format(time.RFC3339Nano),
		Architecture: architecture,
		OS:           "linux",
		Config: struct {
			Env        []string `json:"Env,omitempty"`
			Entrypoint []string `json:"Entrypoint,omitempty"`
			Cmd        []string `json:"Cmd,omitempty"`
			User       string   `json:"User,omitempty"`
			WorkingDir string   `json:"WorkingDir,omitempty"`
		}{exported.Env, exported.Entrypoint, exported.Cmd, exported.User, exported.WorkingDir},
		RootFS: struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		}{Type: "layers", DiffIDs: diffIDs},
	})
	if err != nil {
		return nil, fmt.Errorf("encode OCI image config: %w", err)
	}
	return blob, nil
}

func writeLayerBlob(output, description string, logf func(string, ...any), write func(*tar.Writer) error) (exportedLayer, error) {
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return exportedLayer{}, err
	}
	progress := newLayerProgress(description, logf)
	compressedHash := sha256.New()
	compressedOutput := progressWriter{Writer: io.MultiWriter(file, compressedHash), Add: progress.addCompressed}
	gzipWriter := gzip.NewWriter(compressedOutput)
	gzipWriter.ModTime = time.Unix(0, 0)
	gzipWriter.OS = 255
	uncompressedHash := sha256.New()
	uncompressedOutput := progressWriter{Writer: io.MultiWriter(gzipWriter, uncompressedHash), Add: progress.addProcessed}
	tarWriter := tar.NewWriter(uncompressedOutput)
	fail := func(operationErr error) (exportedLayer, error) {
		return exportedLayer{}, errors.Join(operationErr, tarWriter.Close(), gzipWriter.Close(), file.Close())
	}
	if err := write(tarWriter); err != nil {
		return fail(err)
	}
	if err := tarWriter.Close(); err != nil {
		return fail(err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		return exportedLayer{}, err
	}
	progress.finish()
	info, err := os.Stat(output)
	if err != nil {
		return exportedLayer{}, err
	}
	return exportedLayer{
		descriptor: descriptor{
			MediaType: ociLayerGzipMediaType,
			Digest:    fmt.Sprintf("sha256:%x", compressedHash.Sum(nil)),
			Size:      info.Size(),
		},
		diffID: fmt.Sprintf("sha256:%x", uncompressedHash.Sum(nil)),
		path:   output,
	}, nil
}

const exportProgressInterval = 5 * time.Second

type progressWriter struct {
	io.Writer
	Add func(int64)
}

func (writer progressWriter) Write(data []byte) (int, error) {
	count, err := writer.Writer.Write(data)
	if count > 0 && writer.Add != nil {
		writer.Add(int64(count))
	}
	return count, err
}

type layerProgress struct {
	description string
	logf        func(string, ...any)
	started     time.Time
	lastReport  time.Time
	processed   int64
	compressed  int64
}

func newLayerProgress(description string, logf func(string, ...any)) *layerProgress {
	now := time.Now()
	return &layerProgress{description: description, logf: logf, started: now, lastReport: now}
}

func (progress *layerProgress) addCompressed(count int64) {
	progress.compressed += count
}

func (progress *layerProgress) addProcessed(count int64) {
	progress.processed += count
	now := time.Now()
	if now.Sub(progress.lastReport) < exportProgressInterval {
		return
	}
	progress.lastReport = now
	elapsed := now.Sub(progress.started)
	progress.logf("exporting %s [working] %s processed, %s compressed (%s/s, %s elapsed)",
		progress.description,
		gutil.HumanSize(progress.processed),
		gutil.HumanSize(progress.compressed),
		progressRate(progress.processed, elapsed),
		progressDuration(elapsed),
	)
}

func (progress *layerProgress) finish() {
	elapsed := time.Since(progress.started)
	progress.logf("exported %s: %s processed, %s compressed in %s",
		progress.description,
		gutil.HumanSize(progress.processed),
		gutil.HumanSize(progress.compressed),
		progressDuration(elapsed),
	)
}

type archiveProgress struct {
	logf       func(string, ...any)
	started    time.Time
	lastReport time.Time
	written    int64
	total      int64
}

func newArchiveProgress(total int64, logf func(string, ...any)) *archiveProgress {
	now := time.Now()
	return &archiveProgress{logf: logf, started: now, lastReport: now, total: total}
}

func (progress *archiveProgress) add(count int64) {
	progress.written += count
	now := time.Now()
	if now.Sub(progress.lastReport) < exportProgressInterval {
		return
	}
	progress.lastReport = now
	progress.report(now, false)
}

func (progress *archiveProgress) finish() {
	progress.report(time.Now(), true)
}

func (progress *archiveProgress) report(now time.Time, finished bool) {
	elapsed := now.Sub(progress.started)
	if finished {
		progress.logf("assembled OCI archive: %s copied in %s",
			gutil.HumanSize(progress.written), progressDuration(elapsed))
		return
	}
	percent := 0
	if progress.total > 0 {
		percent = int(progress.written * 100 / progress.total)
		if percent > 100 {
			percent = 100
		}
	}
	progress.logf("writing OCI archive [%s] %3d%% (%s/%s, %s/s, %s elapsed)",
		progressBar(percent),
		percent,
		gutil.HumanSize(progress.written),
		gutil.HumanSize(progress.total),
		progressRate(progress.written, elapsed),
		progressDuration(elapsed),
	)
}

func progressBar(percent int) string {
	const width = 20
	completed := percent * width / 100
	return strings.Repeat("=", completed) + strings.Repeat("·", width-completed)
}

func progressRate(bytes int64, elapsed time.Duration) string {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return "0B"
	}
	return gutil.HumanSize(int64(float64(bytes) / seconds))
}

func progressDuration(elapsed time.Duration) time.Duration {
	if elapsed < time.Second {
		return 0
	}
	return elapsed.Round(time.Second)
}

type erofsTree interface {
	fs.FS
	ReadDir(string) ([]fs.DirEntry, error)
	Lstat(string) (fs.FileInfo, error)
	ReadLink(string) (string, error)
}

func writeEROFSLayer(writer *tar.Writer, base string, extras []string) error {
	primary, err := os.Open(base)
	if err != nil {
		return err
	}
	defer func() { _ = primary.Close() }()
	extraFiles := make([]*os.File, 0, len(extras))
	extraReaders := make([]io.ReaderAt, 0, len(extras))
	for _, extra := range extras {
		file, err := os.Open(extra)
		if err != nil {
			return err
		}
		extraFiles = append(extraFiles, file)
		extraReaders = append(extraReaders, file)
	}
	defer func() {
		for _, file := range extraFiles {
			_ = file.Close()
		}
	}()
	opened, err := erofs.Open(primary, erofs.WithExtraDevices(extraReaders...))
	if err != nil {
		return err
	}
	tree, ok := opened.(erofsTree)
	if !ok {
		return errors.New("EROFS reader does not expose the required export interfaces")
	}
	hardlinks := map[uint64]string{}
	return walkTree(tree, ".", "", func(sourcePath, archivePath string) error {
		header, data, err := erofsTarEntry(tree, sourcePath, archivePath, hardlinks)
		if err != nil {
			return err
		}
		return writeTarEntry(writer, header, data)
	})
}

type readDirTree interface {
	ReadDir(string) ([]fs.DirEntry, error)
}

func walkTree(tree readDirTree, sourceDir, archiveDir string, visit func(string, string) error) error {
	entries, err := tree.ReadDir(sourceDir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		sourcePath := path.Join(sourceDir, entry.Name())
		archivePath := path.Join(archiveDir, entry.Name())
		if err := visit(sourcePath, archivePath); err != nil {
			return err
		}
		if entry.IsDir() {
			if err := walkTree(tree, sourcePath, archivePath, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func erofsTarEntry(tree erofsTree, sourcePath, archivePath string, hardlinks map[uint64]string) (*tar.Header, io.ReadCloser, error) {
	info, err := tree.Lstat(sourcePath)
	if err != nil {
		return nil, nil, err
	}
	header := tarHeader(archivePath, info)
	if ownership, ok := info.(interface {
		UID() uint32
		GID() uint32
	}); ok {
		header.Uid, header.Gid = int(ownership.UID()), int(ownership.GID())
	}
	if attributes, ok := info.(interface{ GetAllXattr() map[string]string }); ok {
		header.PAXRecords = paxAttributes(attributes.GetAllXattr(), nil)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := tree.ReadLink(sourcePath)
		if err != nil {
			return nil, nil, err
		}
		header.Linkname = target
	}
	if device, ok := info.(interface{ Rdev() uint64 }); ok && info.Mode()&fs.ModeDevice != 0 {
		header.Devmajor, header.Devminor = decodeLinuxDevice(uint32(device.Rdev()))
	}
	if inode, ok := info.(interface {
		Ino() uint64
		Nlink() uint64
	}); ok && info.Mode().IsRegular() && inode.Nlink() > 1 {
		if target, seen := hardlinks[inode.Ino()]; seen {
			header.Typeflag = tar.TypeLink
			header.Linkname = target
			header.Size = 0
			return header, nil, nil
		}
		hardlinks[inode.Ino()] = archivePath
	}
	if !info.Mode().IsRegular() {
		return header, nil, nil
	}
	file, err := tree.Open(sourcePath)
	if err != nil {
		return nil, nil, err
	}
	return header, file, nil
}

func writeExt4UpperLayer(writer *tar.Writer, layer *os.File) error {
	info, err := layer.Stat()
	if err != nil {
		return err
	}
	storage, _, err := ext4view.New(layer)
	if err != nil {
		return err
	}
	filesystem, err := ext4.Read(storage, info.Size(), 0, 512)
	if err != nil {
		return err
	}
	defer func() { _ = filesystem.Close() }()
	if _, err := filesystem.Stat("upper"); err != nil {
		return fmt.Errorf("writable layer has no /upper directory: %w", err)
	}
	hardlinks := map[uint32]string{}
	return walkExt4Upper(writer, filesystem, "upper", "", hardlinks)
}

func walkExt4Upper(writer *tar.Writer, filesystem *ext4.FileSystem, sourceDir, archiveDir string, hardlinks map[uint32]string) error {
	attributes, err := filesystem.GetXattr(sourceDir)
	if err != nil {
		return err
	}
	opaque, err := overlayAttributes(attributes)
	if err != nil {
		return fmt.Errorf("%s: %w", sourceDir, err)
	}
	if opaque {
		marker := path.Join(archiveDir, whOpaque)
		if marker == "." {
			marker = whOpaque
		}
		if err := writeTarEntry(writer, &tar.Header{Name: marker, Typeflag: tar.TypeReg, Mode: 0o600, Size: 0}, nil); err != nil {
			return err
		}
	}
	entries, err := filesystem.ReadDir(sourceDir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		sourcePath := path.Join(sourceDir, entry.Name())
		archivePath := path.Join(archiveDir, entry.Name())
		// diskfs' ext4 DirEntry.Info currently reports only the type bits;
		// Stat reads the inode's permissions and special mode bits as well.
		entryInfo, err := filesystem.Stat(sourcePath)
		if err != nil {
			return fmt.Errorf("stat %s: %w", sourcePath, err)
		}
		stat, ok := entryInfo.Sys().(*ext4.StatT)
		if !ok {
			return fmt.Errorf("%s: ext4 metadata has type %T", sourcePath, entryInfo.Sys())
		}
		if whiteout, ok := overlayWhiteoutName(archivePath, entryInfo.Mode(), stat.Major, stat.Minor); ok {
			if err := writeTarEntry(writer, &tar.Header{Name: whiteout, Typeflag: tar.TypeReg, Mode: 0o600, Size: 0}, nil); err != nil {
				return err
			}
			continue
		}
		header := tarHeader(archivePath, entryInfo)
		header.Uid, header.Gid = int(stat.UID), int(stat.GID)
		header.Devmajor, header.Devminor = int64(stat.Major), int64(stat.Minor)
		entryAttributes, err := filesystem.GetXattr(sourcePath)
		if err != nil {
			return err
		}
		if _, err := overlayAttributes(entryAttributes); err != nil {
			return fmt.Errorf("%s: %w", sourcePath, err)
		}
		header.PAXRecords = paxAttributes(nil, entryAttributes)
		if entryInfo.Mode()&fs.ModeSymlink != 0 {
			target, err := filesystem.ReadLink(sourcePath)
			if err != nil {
				return err
			}
			header.Linkname = target
		}
		if entryInfo.Mode().IsRegular() && stat.Nlink > 1 {
			if target, seen := hardlinks[stat.Ino]; seen {
				header.Typeflag = tar.TypeLink
				header.Linkname = target
				header.Size = 0
				if err := writeTarEntry(writer, header, nil); err != nil {
					return err
				}
				continue
			}
			hardlinks[stat.Ino] = archivePath
		}
		var data io.ReadCloser
		if entryInfo.Mode().IsRegular() {
			opened, err := filesystem.Open(sourcePath)
			if err != nil {
				return err
			}
			data = opened
		}
		if err := writeTarEntry(writer, header, data); err != nil {
			return err
		}
		if entryInfo.IsDir() {
			if err := walkExt4Upper(writer, filesystem, sourcePath, archivePath, hardlinks); err != nil {
				return err
			}
		}
	}
	return nil
}

func overlayWhiteoutName(archivePath string, mode fs.FileMode, major, minor uint32) (string, bool) {
	if mode&fs.ModeDevice == 0 || mode&fs.ModeCharDevice == 0 || major != 0 || minor != 0 {
		return "", false
	}
	return path.Join(path.Dir(archivePath), whPrefix+path.Base(archivePath)), true
}

func overlayAttributes(attributes map[string][]byte) (bool, error) {
	opaque := false
	for name, value := range attributes {
		switch name {
		case "trusted.overlay.opaque", "user.overlay.opaque":
			if string(value) == "y" || string(value) == "x" {
				opaque = true
			}
			delete(attributes, name)
		case "trusted.overlay.origin", "user.overlay.origin",
			"trusted.overlay.uuid", "user.overlay.uuid",
			"trusted.overlay.impure", "user.overlay.impure":
			// Origin handles, upper UUIDs, and the impure marker are overlay
			// implementation metadata and are meaningless once the upper is
			// represented as an OCI layer.
			delete(attributes, name)
		case "trusted.overlay.redirect", "user.overlay.redirect", "trusted.overlay.metacopy", "user.overlay.metacopy":
			return false, fmt.Errorf("unsupported overlay metadata %s; export would not reproduce the merged filesystem", name)
		}
	}
	return opaque, nil
}

func paxAttributes(text map[string]string, binary map[string][]byte) map[string]string {
	attributes := make(map[string]string, len(text)+len(binary))
	for name, value := range text {
		attributes["SCHILY.xattr."+name] = value
	}
	for name, value := range binary {
		attributes["SCHILY.xattr."+name] = string(value)
	}
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

func tarHeader(name string, info fs.FileInfo) *tar.Header {
	mode := info.Mode()
	header := &tar.Header{
		Name:       name,
		Mode:       int64(mode.Perm()),
		Size:       info.Size(),
		ModTime:    info.ModTime(),
		AccessTime: info.ModTime(),
		ChangeTime: info.ModTime(),
		Format:     tar.FormatPAX,
	}
	if mode&fs.ModeSetuid != 0 {
		header.Mode |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		header.Mode |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		header.Mode |= 0o1000
	}
	switch {
	case mode.IsRegular():
		header.Typeflag = tar.TypeReg
	case mode.IsDir():
		header.Typeflag = tar.TypeDir
		header.Size = 0
	case mode&fs.ModeSymlink != 0:
		header.Typeflag = tar.TypeSymlink
		header.Size = 0
	case mode&fs.ModeDevice != 0 && mode&fs.ModeCharDevice != 0:
		header.Typeflag = tar.TypeChar
		header.Size = 0
	case mode&fs.ModeDevice != 0:
		header.Typeflag = tar.TypeBlock
		header.Size = 0
	case mode&fs.ModeNamedPipe != 0:
		header.Typeflag = tar.TypeFifo
		header.Size = 0
	case mode&fs.ModeSocket != 0:
		header.Typeflag = 's'
		header.Size = 0
	}
	return header
}

func writeTarEntry(writer *tar.Writer, header *tar.Header, data io.ReadCloser) error {
	if data != nil {
		defer func() { _ = data.Close() }()
	}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %s: %w", header.Name, err)
	}
	if data == nil || header.Size == 0 {
		return nil
	}
	written, err := io.CopyN(writer, data, header.Size)
	if err != nil {
		return fmt.Errorf("write tar content %s: %w", header.Name, err)
	}
	if written != header.Size {
		return fmt.Errorf("short read of %s: got %d of %d bytes", header.Name, written, header.Size)
	}
	return data.Close()
}

func decodeLinuxDevice(device uint32) (major, minor int64) {
	major = int64((device >> 8) & 0xfff)
	minor = int64((device & 0xff) | ((device >> 12) & 0xfff00))
	return major, minor
}
