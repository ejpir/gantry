package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCommandOutputCannotBypassBounds(t *testing.T) {
	var b cappedBuffer
	payload := strings.Repeat("x", 512<<10)
	if n, err := io.Copy(&b, strings.NewReader(payload)); err != nil || n != int64(len(payload)) {
		t.Fatalf("bounded copy: %d, %v", n, err)
	}
	out, truncated := b.result()
	if len(out) != 256<<10 || !truncated {
		t.Fatal("output cap bypassed")
	}
}

func TestExpectedDenialCannotBeAnExecutableFailure(t *testing.T) {
	if expectedExit(nil, false) || expectedExit(errors.New("could not launch"), false) || !expectedExit(nil, true) {
		t.Fatal("infrastructure failure can masquerade as an authorization denial")
	}
}
