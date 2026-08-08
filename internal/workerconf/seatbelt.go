// Seatbelt (SBPL) profile generation. This file is intentionally
// platform-neutral — it is pure string logic — so the Linux CI legs
// test the generator; only apply_darwin.go (sandbox_init) is darwin.

package workerconf

import "strings"

// sbplEscape quotes a path for embedding in an SBPL string literal.
func sbplEscape(p string) string {
	p = strings.ReplaceAll(p, `\`, `\\`)
	p = strings.ReplaceAll(p, `"`, `\"`)
	return p
}

// buildSeatbeltProfile renders the v1 profile for the worker:
// deny-default, the minimal runtime allowances, path access limited to
// the declared FileAllow subpaths (read-only roots get no write rule),
// no network, no exec. Rule order matters in SBPL — later rules win —
// so the blanket deny comes FIRST and every subsequent rule is an
// allow.
func buildSeatbeltProfile(spec Spec) string {
	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n")
	// The Go runtime: thread preemption signals itself; mach-lookup and
	// sysctl-read are needed by runtime/libSystem internals (the M2
	// spike validates the minimal set on real hardware).
	b.WriteString("(allow signal (target self))\n")
	b.WriteString("(allow mach-lookup)\n")
	b.WriteString("(allow sysctl-read)\n")
	// Character devices the runtime and the console/stderr fallback
	// may touch. /dev/null + /dev/urandom only — nothing else exists
	// for this worker.
	b.WriteString(`(allow file-read* file-write* (literal "/dev/null") (literal "/dev/urandom"))` + "\n")
	// Console log + stderr postmortem log: both are pre-opened fds
	// whose writes are path-checked per op under Seatbelt.
	if spec.StateDir != "" {
		b.WriteString(`(allow file-write* (subpath "` + sbplEscape(spec.StateDir) + `"))` + "\n")
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
			rw = append(rw, fa.Path)
		} else {
			ro = append(ro, fa.Path)
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
	}
	if spec.NoExec {
		b.WriteString(";; exec/fork: denied by (deny default) — the worker never spawns\n")
	}
	return b.String()
}
