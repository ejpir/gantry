//go:build unix

package vhostuser

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestAddMemRegRejectsRangePastEOF(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "shared-memory-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	page := int64(os.Getpagesize())
	if err := file.Truncate(page); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	var regions deviceRegions
	err = regions.AddMemReg(fd, &VhostUserMemoryRegion{
		GuestPhysAddr: 0x1000,
		DriverAddr:    0x1000,
		MemorySize:    uint64(page),
		MmapOffset:    uint64(page),
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds fd size") {
		regions.Close()
		t.Fatalf("past-EOF mapping error = %v", err)
	}
}

func TestAddMemRegEnforcesMappedMemoryBudgetBeforeMmap(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	fd, err := syscall.Dup(int(readEnd.Fd()))
	if err != nil {
		t.Fatal(err)
	}

	var regions deviceRegions
	err = regions.AddMemReg(fd, &VhostUserMemoryRegion{
		GuestPhysAddr: 0x1000,
		DriverAddr:    0x1000,
		MemorySize:    maxMappedMemoryBytes + 1,
	})
	if err == nil || !strings.Contains(err.Error(), "mapped memory exceeds") {
		t.Fatalf("oversized mapping error = %v", err)
	}
}

func TestAddMemRegChecksSlotLimitBeforeMapping(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "shared-memory-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	page := int64(os.Getpagesize())
	if err := file.Truncate(page); err != nil {
		t.Fatal(err)
	}
	firstFD, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	var regions deviceRegions
	defer regions.Close()
	if err := regions.AddMemReg(firstFD, &VhostUserMemoryRegion{
		GuestPhysAddr: 0x1000,
		DriverAddr:    0x1000,
		MemorySize:    uint64(page),
	}); err != nil {
		t.Fatal(err)
	}

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	secondFD, err := syscall.Dup(int(readEnd.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	err = regions.AddMemReg(secondFD, &VhostUserMemoryRegion{
		GuestPhysAddr: 0x10000,
		DriverAddr:    0x10000,
		MemorySize:    uint64(page),
	})
	if err == nil || !strings.Contains(err.Error(), "out of memory slots") {
		t.Fatalf("second mapping error = %v", err)
	}
}
