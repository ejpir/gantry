package config

import "testing"

func TestValidateRWLayerSize(t *testing.T) {
	for _, size := range []uint{MinRWLayerSizeMiB, DefaultRWLayerSizeMiB, MaxRWLayerSizeMiB} {
		if err := ValidateRWLayerSize(size); err != nil {
			t.Errorf("ValidateRWLayerSize(%d) = %v", size, err)
		}
	}
	for _, size := range []uint{MinRWLayerSizeMiB - 1, MaxRWLayerSizeMiB + 1} {
		if err := ValidateRWLayerSize(size); err == nil {
			t.Errorf("ValidateRWLayerSize(%d) unexpectedly succeeded", size)
		}
	}
}
