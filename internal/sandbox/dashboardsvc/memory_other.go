//go:build !linux && !darwin && !windows

package dashboardsvc

func hostMemoryBytes() uint64 { return 0 }
