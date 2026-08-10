//go:build linux || darwin

package vmmworker

import (
	"fmt"
	"os"
)

const maxInheritedDisks = 128

func (config Config) validate() error {
	if config.NDisksRO < 0 || config.NDisks < 0 {
		return fmt.Errorf("negative disk count")
	}
	if config.NDisksRO > maxInheritedDisks || config.NDisks > maxInheritedDisks-config.NDisksRO {
		return fmt.Errorf("disk count exceeds limit %d", maxInheritedDisks)
	}
	// RLIMIT_FSIZE is process-wide. Supporting multiple differently sized
	// writable files would let the worker grow a smaller disk up to the
	// largest disk's ceiling. Persistent sandboxes have one writable layer;
	// reject wider tables until each write is mediated by an fd-specific cap.
	if config.NDisks > 1 {
		return fmt.Errorf("split VMM supports at most one writable disk")
	}
	if config.NDisks > 0 && (!config.DisksPrelocked || config.MaxWritableFileSize == 0) {
		return fmt.Errorf("writable disks require a supervisor lock and file-size bound")
	}
	if config.NDisks == 0 && (config.DisksPrelocked || config.MaxWritableFileSize != 0) {
		return fmt.Errorf("writable-disk lock metadata without writable disks")
	}
	return nil
}

func (assets Assets) close() {
	for _, file := range assets.DisksRO {
		if file != nil {
			_ = file.Close()
		}
	}
	for _, file := range assets.Disks {
		if file != nil {
			_ = file.Close()
		}
	}
	for _, file := range []*os.File{assets.Console, assets.Kernel, assets.Rootfs, assets.KVM} {
		if file != nil {
			_ = file.Close()
		}
	}
	if assets.NetConn != nil {
		_ = assets.NetConn.Close()
	}
	if assets.ShareConn != nil {
		_ = assets.ShareConn.Close()
	}
}
