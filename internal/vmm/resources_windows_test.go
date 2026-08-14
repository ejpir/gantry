//go:build windows && amd64

package vmm

import "testing"

func TestValidateResourcesAcceptsWHPXSMP(t *testing.T) {
	if err := ValidateResources(MinMemoryBytes, 2); err != nil {
		t.Fatalf("ValidateResources(..., 2) = %v", err)
	}
}
