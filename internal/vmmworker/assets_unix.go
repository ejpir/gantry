//go:build linux || darwin || windows

package vmmworker

import (
	"fmt"
	"os"
	"runtime"

	"github.com/ejpir/gantry/internal/vmm"
)

const maxInheritedDisks = 128

func (config Config) validate() error {
	if config.WHPXBroker {
		// Validate before the Windows loader derives a dynamic inherited-handle
		// table from VCPUs. The backend validates ordinary configurations again
		// in Prepare; only broker mode needs this pre-loader bound.
		if err := vmm.ValidateResources(config.MemSize, config.VCPUs); err != nil {
			return err
		}
	}
	if config.NDisksRO < 0 || config.NDisks < 0 {
		return fmt.Errorf("negative disk count")
	}
	if config.NDisksRO > maxInheritedDisks || config.NDisks > maxInheritedDisks-config.NDisksRO {
		return fmt.Errorf("disk count exceeds limit %d", maxInheritedDisks)
	}
	if config.DisksBrokered {
		if config.NDisks == 0 {
			return fmt.Errorf("brokered writable disks require at least one disk")
		}
		if len(config.WritableDiskSizes) != config.NDisks {
			return fmt.Errorf("brokered writable disk sizes %d do not match disk count %d", len(config.WritableDiskSizes), config.NDisks)
		}
		for index, size := range config.WritableDiskSizes {
			if size == 0 || size > uint64(^uint64(0)>>1) {
				return fmt.Errorf("brokered writable disk %d has invalid size %d", index, size)
			}
		}
		if config.DisksPrelocked || config.MaxWritableFileSize != 0 {
			return fmt.Errorf("brokered writable disks must not expose file lock metadata")
		}
	} else {
		// RLIMIT_FSIZE is process-wide. Multiple direct writable descriptors
		// with different sizes cannot be bounded safely, so Unix split workers
		// use per-disk brokers and Windows retains the single-disk limit.
		if config.NDisks > 1 {
			return fmt.Errorf("direct split VMM supports at most one writable disk")
		}
		if len(config.WritableDiskSizes) != 0 {
			return fmt.Errorf("writable disk sizes supplied without brokers")
		}
		if runtime.GOOS != "windows" && config.NDisks > 0 && (!config.DisksPrelocked || config.MaxWritableFileSize == 0) {
			return fmt.Errorf("writable disks require a supervisor lock and file-size bound")
		}
		if config.NDisks == 0 && (config.DisksPrelocked || config.MaxWritableFileSize != 0) {
			return fmt.Errorf("writable-disk lock metadata without writable disks")
		}
		if runtime.GOOS == "windows" && (config.DisksPrelocked || config.MaxWritableFileSize != 0) {
			return fmt.Errorf("windows writable disks must be locked by the worker process")
		}
	}
	if config.NoNetwork && len(config.Policy) != 0 {
		return fmt.Errorf("network policy supplied without a network device")
	}
	if config.NoShares && config.VhostShares {
		return fmt.Errorf("vhost shares configured without a share device")
	}
	if config.VhostShares && !config.HasSharedRAM {
		return fmt.Errorf("vhost shares require shared guest RAM")
	}
	if config.HasSharedRAM && !config.VhostShares && !config.WHPXBroker {
		return fmt.Errorf("shared guest RAM requires vhost shares or a WHPX broker")
	}
	if config.WHPXBroker {
		if runtime.GOOS != "windows" || !config.HasSharedRAM || config.WHPXToken == "" {
			return fmt.Errorf("WHPX broker requires Windows shared RAM and a peer token")
		}
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
	for _, conn := range assets.DiskConns {
		if conn != nil {
			_ = conn.Close()
		}
	}
	for _, queue := range assets.VhostQueue {
		for _, file := range []*os.File{queue.KickRead, queue.KickWrite, queue.CallRead, queue.CallWrite} {
			if file != nil {
				_ = file.Close()
			}
		}
	}
	for _, file := range append(
		[]*os.File{assets.Console, assets.Kernel, assets.Rootfs, assets.SharedRAM, assets.WHPXMailbox, assets.WHPXRequestEvent, assets.KVM},
		assets.WHPXReplyEvents...,
	) {
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
	if assets.WHPXConn != nil {
		_ = assets.WHPXConn.Close()
	}
}
