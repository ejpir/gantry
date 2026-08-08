//go:build linux && amd64

package main

// defaultPlatform pins runsc's platform on x86_64 guests: the slim
// nerdbox guest kernel hangs systrap's newSubprocess (field-proven on
// c5.metal — the sentry's first stub process never reaches its sync
// point, both gofer and sandbox sit idle, the startup watchdog fires,
// and `runsc start` then fails with "state stopped"). The same kernel
// and runsc build drive systrap fine on arm64 HVF, and the AL2023 host
// kernel drives systrap fine on the same metal — the gap is a guest
// kernel feature systrap needs. ptrace needs nothing beyond PTRACE,
// which the kernel has. The cmdline knob crunshim.platform=systrap
// opts back in (e.g. to re-test against a kernel with the gap closed).
const defaultPlatform = "ptrace"
