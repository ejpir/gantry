//go:build windows && amd64

package vmm

import (
	"strings"
	"testing"
)

func TestValidateResourcesRejectsUnverifiedWHPXSMP(t *testing.T) {
	err := ValidateResources(MinMemoryBytes, 2)
	if err == nil || !strings.Contains(err.Error(), "exactly one vCPU") {
		t.Fatalf("ValidateResources(..., 2) = %v", err)
	}
}
