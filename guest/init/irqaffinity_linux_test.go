//go:build linux

package main

import (
	"reflect"
	"testing"
)

func TestCPUListSize(t *testing.T) {
	for _, test := range []struct {
		list string
		want int
	}{
		{list: "0", want: 1},
		{list: "0-11", want: 12},
		{list: "0-3,8,10-11", want: 12},
	} {
		got, err := cpuListSize(test.list)
		if err != nil || got != test.want {
			t.Errorf("cpuListSize(%q) = %d, %v; want %d", test.list, got, err, test.want)
		}
	}
	for _, invalid := range []string{"x", "3-1", "-1"} {
		if _, err := cpuListSize(invalid); err == nil {
			t.Errorf("cpuListSize(%q) succeeded", invalid)
		}
	}
}

func TestVirtioIRQRoutings(t *testing.T) {
	interrupts := `            CPU0 CPU1 CPU2 CPU3
 11: 1 2 3 4 GICv3 27 Level arch_timer
 14: 99 0 0 0 GICv3 73 Edge virtio25
 42: 20 0 0 0 GICv3 74 Edge virtio26
 43: 10 0 0 0 GICv3 75 Edge virtio27
IPI0: 1 1 1 1 Rescheduling interrupts
 44: 1 0 0 0 GICv3 76 Edge virtio-nope
`
	want := []virtioIRQRoute{{irq: 14, target: 1}, {irq: 42, target: 2}, {irq: 43, target: 3}}
	if got := virtioIRQRoutings(interrupts, 12); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %#v, want %#v", got, want)
	}
	if got := virtioIRQRoutings(interrupts, 1); got != nil {
		t.Fatalf("single-CPU routes = %#v, want nil", got)
	}
}
