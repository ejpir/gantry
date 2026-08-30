package vmmworker

import "testing"

func TestConfigAllowsMultipleDirectWritableDisks(t *testing.T) {
	if err := (Config{NDisks: 2}).validate(); err != nil {
		t.Fatalf("valid multi-disk descriptor table: %v", err)
	}
}
