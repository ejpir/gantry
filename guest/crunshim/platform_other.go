//go:build linux && !amd64

package main

// Non-x86 guests run runsc's own platform auto-detection: systrap
// works on the slim nerdbox kernel under arm64 HVF (the create-hang
// fixes of 2026-08-03 were validated against it).
const defaultPlatform = ""
