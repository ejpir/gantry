package vmmworker

import "testing"

func TestWindowsSplitVMMDoesNotRequireNetworkOrShareAttachment(t *testing.T) {
	if !vmmSplitPossible("required", nil, nil) {
		t.Fatal("required split VMM rejected an offline, shareless topology")
	}
	if vmmSplitPossible("off", nil, nil) {
		t.Fatal("off mode enabled the split VMM")
	}
}
