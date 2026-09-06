package dashboardsvc

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var globalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

func hostMemoryBytes() uint64 {
	// MEMORYSTATUSEX reports physical RAM usable by the OS, excluding swap.
	var info struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}
	info.Length = uint32(unsafe.Sizeof(info))
	ok, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return 0
	}
	return info.TotalPhys
}
