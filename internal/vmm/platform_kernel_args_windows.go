//go:build windows

package vmm

import "fmt"

func platformKernelArgs(cmdline, arch string) (string, error) {
	if arch != "amd64" || kernelArgPresent(cmdline, "tsc_early_khz") {
		return cmdline, nil
	}
	frequency, err := whpxProcessorClockFrequency()
	if err != nil {
		return cmdline, err
	}
	// Reject an implausible capability instead of silently distorting guest
	// time. Current x86 TSC rates sit comfortably inside these broad bounds.
	if frequency < 100_000_000 || frequency > 20_000_000_000 {
		return cmdline, fmt.Errorf("implausible WHPX processor clock frequency %d Hz", frequency)
	}
	khz := (frequency + 500) / 1000
	fmt.Printf("WHPX: processor clock %d Hz; using tsc_early_khz=%d\n", frequency, khz)
	return insertKernelArgs(cmdline, fmt.Sprintf("tsc_early_khz=%d", khz)), nil
}
