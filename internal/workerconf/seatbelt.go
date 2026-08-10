// Seatbelt (SBPL) profile generation. This file is intentionally
// platform-neutral — it is pure string logic — so the Linux CI legs
// test the generator; only apply_darwin.go (sandbox_init) is darwin.

package workerconf

import (
	"path/filepath"
	"strings"
)

// seatbeltRuntimeSysctls are the exact Darwin values queried by the current Go
// runtime during CPU/OS initialization. Keeping the names explicit prevents
// the broad sysctl-read operation from exposing KERN_PROC process listings.
var seatbeltRuntimeSysctls = []string{
	"hw.ncpu",
	"hw.pagesize",
	"hw.optional.armv8_1_atomics",
	"hw.optional.armv8_crc32",
	"hw.optional.armv8_2_sha512",
	"hw.optional.armv8_2_sha3",
	"hw.optional.arm.FEAT_DIT",
	"kern.osrelease",
	"sysctl.proc_translated",
}

// sbplEscape quotes a path for embedding in an SBPL string literal.
func sbplEscape(p string) string {
	p = strings.ReplaceAll(p, `\`, `\\`)
	p = strings.ReplaceAll(p, `"`, `\"`)
	return p
}

// sbplPath canonicalizes a path for a Seatbelt rule: the kernel
// matches against REAL paths and macOS staples are symlink farms
// (/var -> /private/var, /tmp -> /private/tmp — the M2 spike's rw
// export under $TMPDIR was DENIED until this). Unresolvable paths fall
// back to the raw form (the rule then simply never matches, which
// fails closed).
func sbplPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
		return r
	}
	return p
}

// buildSeatbeltProfile renders the v1 profile for the worker:
// deny-default, the minimal runtime allowances, path access limited to
// the declared FileAllow subpaths (read-only roots get no write rule),
// role-scoped network access, no exec. Rule order matters in SBPL — later rules win —
// so the blanket deny comes FIRST and every subsequent rule is an
// allow.
func buildSeatbeltProfile(spec Spec) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n")
	// The Go runtime uses self-signals for thread preemption. Hypervisor.framework
	// enters HVF through Mach traps, not bootstrap service lookup, so neither
	// worker role receives ambient XPC/Mach-service discovery authority.
	b.WriteString("(allow signal (target self))\n")
	b.WriteString("(allow sysctl-read\n")
	for _, name := range seatbeltRuntimeSysctls {
		b.WriteString("\t(sysctl-name \"" + name + "\")\n")
	}
	if spec.Profile == ProfileVMM {
		// Hypervisor.framework uses this feature bit when selecting its VM
		// creation path. It reveals no process-specific information.
		b.WriteString("\t(sysctl-name \"kern.hv_support\")\n")
	}
	b.WriteString(")\n")
	// Minimal runtime devices. Diagnostics are inherited pipes, never a path.
	b.WriteString(`(allow file-read* file-write* (literal "/dev/null"))` + "\n")
	b.WriteString(`(allow file-read* (literal "/dev/urandom"))` + "\n")
	for _, p := range spec.ReadFiles {
		if p != "" {
			b.WriteString(`(allow file-read* (literal "` + sbplEscape(sbplPath(p)) + `"))` + "\n")
		}
	}
	// Share export roots, split by writability: a RO export never
	// appears in a write rule (defense in depth behind the hub's own
	// O_PATH enforcement).
	var ro, rw []string
	for _, fa := range spec.FileAllow {
		if fa.Path == "" {
			continue
		}
		if fa.Write {
			rw = append(rw, sbplPath(fa.Path))
		} else {
			ro = append(ro, sbplPath(fa.Path))
		}
	}
	writeAllow := func(ops string, paths []string) {
		if len(paths) == 0 {
			return
		}
		b.WriteString("(allow " + ops + "\n")
		for _, p := range paths {
			b.WriteString("\t(subpath \"" + sbplEscape(p) + "\")\n")
		}
		b.WriteString(")\n")
	}
	writeAllow("file-read*", ro)
	writeAllow("file-read* file-write*", rw)
	// No network, no exec, no fork: deny default already covers them;
	// named here as documentation of the contract.
	if spec.NoNetwork {
		b.WriteString(";; network: denied by (deny default) — data plane is pre-opened fds\n")
	} else {
		// The network worker is the host TCP/UDP proxy and port-listener owner.
		// These IP-qualified rules deliberately omit AF_UNIX system-socket
		// authority and Mach IPC. The worker's egress policy remains the
		// finer-grained destination boundary within the required INET surface.
		b.WriteString("(allow network-bind (local ip \"*:*\"))\n")
		b.WriteString("(allow network-inbound)\n")
		b.WriteString("(allow network-outbound)\n")
	}
	if spec.NoExec {
		b.WriteString(";; exec/fork: denied by (deny default) — the worker never spawns\n")
	}
	return b.String()
}
