//go:build linux

// spikecheck runs inside a container whose rootfs is a virtio-fs hub export
// (docs/kubernetes-runtimeclass.md, Phase K0 dynamic-rootfs spike). It
// verifies the OCI rootfs semantics the design requires from an exported
// containerd snapshot: overlay whiteouts, xattrs, hard links, device nodes,
// locks, mmap, rename, fsync, ownership/setuid bits, and host-enforced
// read-only behavior, then measures metadata and I/O performance.
//
// Modes: default = rw battery; -ro = every write must be rejected; -perf =
// measurements only. Every check prints "CHECK <name> PASS|FAIL|WARN <detail>"
// and the process exits 1 if any check failed. PERF lines carry measurements.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	roMode      = flag.Bool("ro", false, "verify host-enforced read-only export semantics")
	perfMode    = flag.Bool("perf", false, "run performance measurements instead of the semantics battery")
	whiteout    = flag.String("whiteout", "", "lower-layer path hidden by an overlay whiteout")
	perfSizeMiB = flag.Int("perf-mib", 64, "size of the perf write/read file")
)

var failed bool

func check(name string, err error, detail string) {
	if err != nil {
		failed = true
		fmt.Printf("CHECK %-22s FAIL %s: %v\n", name, detail, err)
		return
	}
	fmt.Printf("CHECK %-22s PASS %s\n", name, detail)
}

// checkRejected passes when op fails the way a read-only filesystem must
// reject it (EROFS/EPERM), and fails when the operation unexpectedly succeeds.
func checkRejected(name string, op func() error, cleanup func()) {
	err := op()
	if cleanup != nil {
		cleanup()
	}
	if err == nil {
		failed = true
		fmt.Printf("CHECK %-22s FAIL write unexpectedly succeeded on a read-only export\n", name)
		return
	}
	if errorsIsRO(err) {
		fmt.Printf("CHECK %-22s PASS rejected with %v\n", name, err)
		return
	}
	failed = true
	fmt.Printf("CHECK %-22s FAIL rejected with an unexpected error: %v\n", name, err)
}

func errorsIsRO(err error) bool {
	return strings.Contains(err.Error(), "read-only") || strings.Contains(err.Error(), "operation not permitted")
}

// errorsIsUnimplemented reports a filesystem operation the export backend
// does not serve at all.
func errorsIsUnimplemented(err error) bool {
	return strings.Contains(err.Error(), "function not implemented") || strings.Contains(err.Error(), "operation not supported")
}

func main() {
	flag.Parse()
	switch {
	case *perfMode:
		runPerf()
	case *roMode:
		runReadOnly()
	default:
		runBattery()
	}
	if failed {
		os.Exit(1)
	}
}

func runBattery() {
	readChecks()
	writeChecks()
}

func readChecks() {
	// identity: the export really is the snapshot's merged image content.
	osRelease, err := os.ReadFile("/etc/os-release")
	if err == nil && !strings.Contains(string(osRelease), "NAME=") {
		err = fmt.Errorf("malformed os-release: %q", osRelease)
	}
	check("identity", err, "/etc/os-release from the exported lower layer")

	marker, err := os.ReadFile("/spike-upper-marker")
	if err == nil && string(marker) != "gantry-rootfs-spike\n" {
		err = fmt.Errorf("marker content %q", marker)
	}
	check("upper-marker", err, "upper-layer file visible through the export")

	if *whiteout != "" {
		_, err := os.Lstat(*whiteout)
		if err == nil {
			err = fmt.Errorf("%s is visible despite its overlay whiteout", *whiteout)
		} else if os.IsNotExist(err) {
			err = nil
		}
		check("whiteout", err, *whiteout)
	}

	infoA, errA := os.Stat("/spike-hard-a")
	infoB, errB := os.Stat("/spike-hard-b")
	err = nil
	if errA != nil || errB != nil {
		err = fmt.Errorf("stat: %v / %v", errA, errB)
	} else if !os.SameFile(infoA, infoB) {
		err = fmt.Errorf("not the same inode")
	} else if stat, ok := infoA.Sys().(*syscall.Stat_t); !ok || stat.Nlink < 2 {
		err = fmt.Errorf("nlink %d, want >= 2", infoA.Sys())
	}
	check("hardlink", err, "hard-linked pair keeps one inode")

	info, err := os.Stat("/spike-setuid")
	if err == nil && info.Mode()&os.ModeSetuid == 0 {
		err = fmt.Errorf("mode %v lost the setuid bit", info.Mode())
	}
	check("setuid-bit", err, "setuid bit survives the export")

	if _, statErr := os.Lstat("/spike-dev-null"); os.IsNotExist(statErr) {
		// macOS hosts cannot mknod the fixture without privileges.
		fmt.Println("CHECK device-node            SKIP host prep did not provide the fixture")
		return
	}
	var stat unix.Stat_t
	err = unix.Stat("/spike-dev-null", &stat)
	if err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
			err = fmt.Errorf("mode %o, want character device", stat.Mode)
		} else if unix.Major(uint64(stat.Rdev)) != 1 || unix.Minor(uint64(stat.Rdev)) != 3 {
			err = fmt.Errorf("rdev %d, want 1:3", stat.Rdev)
		}
	}
	check("device-node", err, "upper-layer char device 1:3")
}

func writeChecks() {
	const xattrTarget = "/spike-xattr-target"
	f, err := os.Create(xattrTarget)
	stage := "create"
	if err == nil {
		_ = f.Close()
		stage = "set"
		err = unix.Setxattr(xattrTarget, "user.spike", []byte("rootfs"), 0)
	}
	if err == nil {
		stage = "get"
		var value []byte
		size, e := unix.Getxattr(xattrTarget, "user.spike", nil)
		if e == nil && size > 0 {
			value = make([]byte, size)
			_, e = unix.Getxattr(xattrTarget, "user.spike", value)
		}
		err = e
		if err == nil && string(value) != "rootfs" {
			err = fmt.Errorf("xattr round-trip %q", value)
		}
	}
	if err != nil {
		err = fmt.Errorf("%s: %w", stage, err)
	}
	check("xattr", err, "user.* xattr set/get on an exported file")

	flockFd, err := unix.Open("/spike-flock-target", unix.O_CREAT|unix.O_RDWR, 0o600)
	if err == nil {
		err = unix.Flock(flockFd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			err = unix.Flock(flockFd, unix.LOCK_UN)
		}
		_ = unix.Close(flockFd)
	}
	check("flock", err, "advisory lock across the export")

	const mmapTarget = "/spike-mmap-target"
	mmapFd, err := unix.Open(mmapTarget, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC, 0o600)
	if err == nil {
		err = unix.Ftruncate(mmapFd, 1<<20)
	}
	if err == nil {
		var data []byte
		data, err = unix.Mmap(mmapFd, 0, 1<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err == nil {
			copy(data, []byte("gantry-mmap"))
			err = unix.Msync(data, unix.MS_SYNC)
			_ = unix.Munmap(data)
		}
		_ = unix.Close(mmapFd)
	}
	if err == nil {
		var back []byte
		back, err = os.ReadFile(mmapTarget)
		if err == nil && !strings.HasPrefix(string(back), "gantry-mmap") {
			err = fmt.Errorf("mmap content mismatch")
		}
	}
	check("mmap", err, "shared mmap write + msync + read back")

	err = func() error {
		if err := os.WriteFile("/spike-rename-a", []byte("rename-payload"), 0o600); err != nil {
			return err
		}
		if err := syncFile("/spike-rename-a"); err != nil {
			return err
		}
		if err := os.Rename("/spike-rename-a", "/spike-rename-b"); err != nil {
			return err
		}
		back, err := os.ReadFile("/spike-rename-b")
		if err == nil && string(back) != "rename-payload" {
			return fmt.Errorf("rename content mismatch")
		}
		return err
	}()
	check("rename-fsync", err, "write + fsync + rename + read back")

	err = func() error {
		if err := os.Symlink("/etc/os-release", "/spike-symlink"); err != nil {
			return err
		}
		target, err := os.Readlink("/spike-symlink")
		if err == nil && target != "/etc/os-release" {
			return fmt.Errorf("readlink %q", target)
		}
		return err
	}()
	check("symlink", err, "symlink create + readlink on the export")

	// Guest-side mknod must be DENIED: sharefs rejects special-file
	// creation on every writable export by policy (a guest must never plant
	// device nodes on the host). Device-node content arrives host-side via
	// preflighted fixtures (checked above).
	err = unix.Mknod("/spike-mknod", unix.S_IFCHR|0o600, int(unix.Mkdev(5, 0)))
	if err == nil {
		_ = os.Remove("/spike-mknod")
		check("mknod-denied", errors.New("guest-created device node accepted — export policy must deny mknod"), "")
	} else if errorsIsRO(err) || errorsIsUnimplemented(err) {
		fmt.Printf("CHECK %-22s PASS guest mknod denied by export policy: %v\n", "mknod-denied", err)
	} else {
		check("mknod-denied", err, "guest mknod rejected with an unexpected error (want EPERM/ENOSYS)")
	}

	// The host side verifies this file lands in the overlay upper directory.
	err = os.WriteFile("/spike-guest-write", []byte("from-guest\n"), 0o644)
	if err == nil {
		err = syncFile("/spike-guest-write")
	}
	check("guest-write", err, "write + fsync for host-side verification")
}

func runReadOnly() {
	readChecks()
	checkRejected("ro-write", func() error {
		return os.WriteFile("/spike-ro-must-fail", []byte("x"), 0o644)
	}, func() { _ = os.Remove("/spike-ro-must-fail") })
	checkRejected("ro-xattr", func() error {
		return unix.Setxattr("/spike-upper-marker", "user.spike", []byte("x"), 0)
	}, nil)
	checkRejected("ro-rename", func() error {
		return os.Rename("/spike-upper-marker", "/spike-upper-marker-moved")
	}, nil)
}

func runPerf() {
	started := time.Now()
	entries := 0
	walkErr := filepath.WalkDir("/usr", func(_ string, _ os.DirEntry, err error) error {
		if err == nil {
			entries++
		}
		return nil
	})
	walkElapsed := time.Since(started)
	check("perf-walk", walkErr, fmt.Sprintf("%d entries in /usr", entries))

	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	const target = "/spike-perf-file"
	writeStarted := time.Now()
	var writeErr error
	for i := 0; i < *perfSizeMiB; i++ {
		if writeErr = appendChunk(target, payload, i == 0); writeErr != nil {
			break
		}
	}
	if err := syncFile(target); writeErr == nil {
		writeErr = err
	}
	writeElapsed := time.Since(writeStarted)
	check("perf-write", writeErr, fmt.Sprintf("%d MiB", *perfSizeMiB))

	readStarted := time.Now()
	readBytes, readErr := readAll(target)
	readElapsed := time.Since(readStarted)
	if readErr == nil && readBytes != int64(*perfSizeMiB)<<20 {
		readErr = fmt.Errorf("read %d bytes, want %d MiB", readBytes, *perfSizeMiB)
	}
	check("perf-read", readErr, fmt.Sprintf("%d MiB", *perfSizeMiB))
	_ = os.Remove(target)

	if !failed {
		fmt.Printf("PERF walk_entries=%d walk=%s write_mib_s=%.1f read_mib_s=%.1f\n",
			entries, walkElapsed.Round(time.Millisecond),
			float64(*perfSizeMiB)/writeElapsed.Seconds(),
			float64(*perfSizeMiB)/readElapsed.Seconds())
	}
}

func appendChunk(path string, chunk []byte, first bool) error {
	flags := os.O_CREATE | os.O_WRONLY
	if first {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(chunk)
	return err
}

func readAll(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	return io.Copy(io.Discard, f)
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}
