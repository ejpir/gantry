//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type virtioIRQRoute struct {
	irq    int
	target int
}

// virtioIRQRoutings mirrors the VMM's slot%vcpus policy. Linux names a
// virtio-mmio device by its slot (virtio0, virtio1, ...), so no unstable IRQ
// number or device-probe ordering table needs to be baked into the guest.
func virtioIRQRoutings(interrupts string, vcpus int) []virtioIRQRoute {
	if vcpus <= 1 {
		return nil
	}
	var routes []virtioIRQRoute
	for _, line := range strings.Split(interrupts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		irq, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil {
			continue
		}
		name := fields[len(fields)-1]
		if !strings.HasPrefix(name, "virtio") {
			continue
		}
		slot, err := strconv.Atoi(strings.TrimPrefix(name, "virtio"))
		if err != nil || slot < 0 {
			continue
		}
		routes = append(routes, virtioIRQRoute{irq: irq, target: slot % vcpus})
	}
	return routes
}

func cpuListSize(list string) (int, error) {
	maximum := -1
	for _, part := range strings.Split(strings.TrimSpace(list), ",") {
		bounds := strings.SplitN(part, "-", 2)
		end, err := strconv.Atoi(bounds[len(bounds)-1])
		if err != nil || end < 0 {
			return 0, fmt.Errorf("invalid CPU list %q", list)
		}
		if len(bounds) == 2 {
			start, startErr := strconv.Atoi(bounds[0])
			if startErr != nil || start < 0 || start > end {
				return 0, fmt.Errorf("invalid CPU list %q", list)
			}
		}
		if end > maximum {
			maximum = end
		}
	}
	return maximum + 1, nil
}

func readCPUListSize(path string) (int, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return cpuListSize(string(value))
}

func spreadVirtioIRQs() {
	vcpus, err := readCPUListSize("/sys/devices/system/cpu/present")
	if err != nil || vcpus <= 1 {
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		online, onlineErr := readCPUListSize("/sys/devices/system/cpu/online")
		if onlineErr == nil && online >= vcpus {
			break
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}

	interrupts, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		fmt.Printf("[init] read interrupts for affinity: %v\n", err)
		return
	}
	configured := 0
	for _, route := range virtioIRQRoutings(string(interrupts), vcpus) {
		path := fmt.Sprintf("/proc/irq/%d/smp_affinity_list", route.irq)
		if err := os.WriteFile(path, []byte(strconv.Itoa(route.target)), 0o644); err != nil {
			fmt.Printf("[init] route irq %d to cpu %d: %v\n", route.irq, route.target, err)
			continue
		}
		configured++
	}
	if configured != 0 {
		fmt.Printf("[init] spread %d virtio IRQs across %d CPUs\n", configured, vcpus)
	}
}
