//go:build windows

package devices

import "testing"

func TestIOApicIDStartsAtMPSValueAndIsWritable(t *testing.T) {
	a := NewIOAPIC(2, nil)
	if got := a.readReg(0); got != 2<<24 {
		t.Fatalf("initial ID register = %#x, want %#x", got, 2<<24)
	}
	a.writeReg(0, 7<<24)
	if got := a.readReg(0); got != 7<<24 {
		t.Fatalf("written ID register = %#x, want %#x", got, 7<<24)
	}
}
