//go:build darwin

// seatbeltspike is the M2 real-hardware probe for worker confinement
// (docs/worker-confinement.md): it applies EXACTLY the worker's
// Seatbelt profile via the same code path (workerconf.Apply/Verify)
// and answers, on a real Mac, the questions the design cannot answer
// from source alone:
//
//   - does the Go runtime survive a deny-default Seatbelt profile?
//   - does hv_vm_create still work post-Apply (mach traps are not
//     Seatbelt-filtered — in theory)?
//   - are the denied properties actually denied (fs/net/exec)?
//   - do path-checked writes still work on pre-opened fds OUTSIDE the
//     allowed subpaths (the console-log grandfathering question)?
//   - do RO exports stay read-only while RW exports stay writable?
//
// Build + sign + run (the HVF probe needs the entitlement):
//
//	go build -o /tmp/seatbeltspike ./cmd/seatbeltspike
//	codesign --sign - --entitlements config/entitlements.plist -f /tmp/seatbeltspike
//	/tmp/seatbeltspike
//
// Diagnostic tool; like cmd/dbgnetspawn it is removed before release.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ejpir/gantry/internal/workerconf"
)

type probe struct {
	name   string
	result string
	detail string
}

func main() {
	if isExtChild() {
		runExtChild(os.Args[2])
		return
	}
	if isExtSpike() {
		runExtSpike()
		return
	}
	fmt.Printf("seatbeltspike — M2 probe on %s/%s (docs/worker-confinement.md)\n\n", runtime.GOOS, runtime.GOARCH)

	// ---- setup (pre-Apply): a fake state dir, RO + RW "exports", and
	// a file OUTSIDE every allowance that stays OPEN across Apply.
	base, err := os.MkdirTemp("", "seatbeltspike-*")
	must("tempdir", err)
	defer func() { _ = os.RemoveAll(base) }()
	stateDir := filepath.Join(base, "state")
	roDir := filepath.Join(base, "ro-export")
	rwDir := filepath.Join(base, "rw-export")
	for _, d := range []string{stateDir, roDir, rwDir} {
		must("mkdir "+d, os.MkdirAll(d, 0o755))
	}
	must("seed ro", os.WriteFile(filepath.Join(roDir, "file"), []byte("ro"), 0o644))
	must("seed rw", os.WriteFile(filepath.Join(rwDir, "file"), []byte("rw"), 0o644))
	outside, err := os.CreateTemp("", "seatbeltspike-outside-*.log")
	must("outside fd", err)
	defer func() { _ = outside.Close() }()
	must("outside prewrite", os.WriteFile(outside.Name(), []byte("pre"), 0o644))

	// ---- pre-Apply sanity: network is reachable (ECONNREFUSED still
	// proves the syscall path works).
	if c, err := net.DialTimeout("tcp", "127.0.0.1:9", 100*time.Millisecond); err == nil && c != nil {
		_ = c.Close()
	}
	fmt.Println("pre-apply sanity: setup complete, applying Seatbelt profile")

	// ---- Apply EXACTLY the worker's spec.
	spec := workerconf.DefaultSpec(64, "")
	spec.WriteFiles = []string{filepath.Join(stateDir, "console.log")}
	spec.FileAllow = []workerconf.FileAllowance{
		{Path: roDir, Write: false},
		{Path: rwDir, Write: true},
	}
	rep, applyErr := workerconf.Apply(spec)
	if applyErr != nil {
		fmt.Printf("APPLY FAILED: %v (report %+v)\n", applyErr, rep)
		os.Exit(1)
	}
	fmt.Printf("apply: %v\n\n", rep.Notes)

	// ---- runtime survival: allocations, GC, goroutines, a timer.
	func() {
		done := make(chan struct{})
		for i := 0; i < 64; i++ {
			go func() { time.Sleep(5 * time.Millisecond); done <- struct{}{} }()
		}
		for i := 0; i < 64; i++ {
			<-done
		}
		runtime.GC()
		t := time.NewTimer(10 * time.Millisecond)
		<-t.C
	}()

	// ---- the worker's own verifier (same probes, same schema).
	workerconf.Verify(spec, rep)
	fmt.Println("verifier report (identical to what the worker reports):")
	for _, p := range rep.Results {
		fmt.Printf("  %-10s %-14s %s\n", p.Property, p.State, p.Detail)
	}

	// ---- spike-only probes.
	var probes []probe

	// HVF: the make-or-break question.
	hvOK, hvDetail := probeHVF()
	probes = append(probes, probe{"hv_vm_create", verdict(hvOK, true), hvDetail})

	// Writes to a pre-opened fd outside the allowances: grandfathered?
	if _, err := outside.WriteString("post"); err != nil {
		probes = append(probes, probe{"grandfather-fd", "DENIED", err.Error()})
	} else {
		probes = append(probes, probe{"grandfather-fd", "ALLOWED", "write to pre-opened fd outside allowances succeeded"})
	}

	// RO export must stay read-only; RW must stay writable.
	roTarget := filepath.Join(roDir, "newfile")
	if f, err := os.Create(roTarget); err == nil {
		_ = f.Close()
		probes = append(probes, probe{"ro-export write", "ALLOWED (!!)", "RO export accepted a create — profile bug"})
	} else {
		probes = append(probes, probe{"ro-export write", "DENIED", errString(err)})
	}
	rwTarget := filepath.Join(rwDir, "newfile")
	if f, err := os.Create(rwTarget); err == nil {
		_ = f.Close()
		probes = append(probes, probe{"rw-export write", "ALLOWED", "create in RW export works"})
	} else {
		probes = append(probes, probe{"rw-export write", "DENIED (!!)", errString(err)})
	}

	// State dir write (console/stderr viability).
	if f, err := os.Create(filepath.Join(stateDir, "console.log")); err == nil {
		_ = f.Close()
		probes = append(probes, probe{"statedir write", "ALLOWED", "console/stderr logs viable"})
	} else {
		probes = append(probes, probe{"statedir write", "DENIED (!!)", errString(err)})
	}

	// Config tamper (the Codex finding's attack path): anything else
	// under the state dir — sandbox.json above all — must be DENIED.
	if f, err := os.Create(filepath.Join(stateDir, "sandbox.json")); err == nil {
		_ = f.Close()
		probes = append(probes, probe{"config tamper", "ALLOWED (!!)", "worker can rewrite trusted sandbox state"})
	} else {
		probes = append(probes, probe{"config tamper", "DENIED", "sandbox.json protected (" + errString(err) + ")"})
	}

	// Exec: must be denied.
	if err := exec.Command("/bin/true").Run(); err != nil {
		probes = append(probes, probe{"exec /bin/true", "DENIED", errString(err)})
	} else {
		probes = append(probes, probe{"exec /bin/true", "ALLOWED (!!)", "exec succeeded — profile bug"})
	}

	fmt.Println("\nspike-only probes:")
	for _, p := range probes {
		fmt.Printf("  %-16s %-12s %s\n", p.name, p.result, p.detail)
	}

	fmt.Print("\nverdict: ")
	switch {
	case hvOK:
		fmt.Println("HVF WORKS UNDER SEATBELT — the M2 enforcer design is viable; wire mode=auto on macOS next.")
	default:
		fmt.Println("HVF FAILED UNDER SEATBELT — macOS confinement needs a redesign (see docs/worker-confinement.md).")
	}
}

func verdict(ok, want bool) string {
	if ok == want {
		return "OK"
	}
	return "FAILED"
}

// probeHVF calls hv_vm_create(NULL)/hv_vm_destroy via the same purego
// pattern as internal/vmm. Requires the hypervisor entitlement (see
// the build comment above).
func probeHVF() (bool, string) {
	lib, err := purego.Dlopen("/System/Library/Frameworks/Hypervisor.framework/Hypervisor",
		purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return false, "dlopen: " + err.Error()
	}
	var hvVmCreate func(config uintptr) uint32
	var hvVmDestroy func() uint32
	sym, err := purego.Dlsym(lib, "hv_vm_create")
	if err != nil {
		return false, "dlsym hv_vm_create: " + err.Error()
	}
	purego.RegisterFunc(&hvVmCreate, sym)
	sym, err = purego.Dlsym(lib, "hv_vm_destroy")
	if err != nil {
		return false, "dlsym hv_vm_destroy: " + err.Error()
	}
	purego.RegisterFunc(&hvVmDestroy, sym)
	rc := hvVmCreate(0)
	if rc != 0 {
		return false, fmt.Sprintf("hv_vm_create=%#x (HV_SUCCESS=0; nonzero without the entitlement or under confinement)", rc)
	}
	_ = hvVmDestroy()
	return true, "hv_vm_create(0)=HV_SUCCESS, destroyed"
}

func must(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "seatbeltspike: %s: %v\n", what, err)
		os.Exit(1)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---------------------------------------------------------------- M2.5
// sandbox extensions: the candidate fix for share hot-add under
// Seatbelt. Production flow, reproduced here: the UNSANDBOXED
// supervisor issues an extension token for the new share path; the
// CONFINED worker consumes it and only then can open below the passed
// root descriptor. Answers: can a non-root unsandboxed process issue?
// Does consumption work under our deny-default profile? Does it lift
// the dirfd-relative openat path check?
//
// Run: /tmp/seatbeltspike -extensions

var (
	sandboxExtensionIssueFile          func(path *byte, flags uint64) *byte
	sandboxExtensionIssueFileToProcess func(path *byte, flags uint64, pid int32) *byte
	sandboxExtensionConsume            func(token *byte) int64
	sandboxExtensionRelease            func(handle int64)
)

func extInit() error {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return err
	}
	for sym, fn := range map[string]any{
		"sandbox_extension_issue_file":            &sandboxExtensionIssueFile,
		"sandbox_extension_issue_file_to_process": &sandboxExtensionIssueFileToProcess,
		"sandbox_extension_consume":               &sandboxExtensionConsume,
		"sandbox_extension_release":               &sandboxExtensionRelease,
	} {
		p, err := purego.Dlsym(lib, sym)
		if err != nil {
			return fmt.Errorf("dlsym %s: %w", sym, err)
		}
		purego.RegisterFunc(fn, p)
	}
	return nil
}

func cstr(s string) *byte { b := append([]byte(s), 0); return &b[0] }

// readCStr reads a NUL-terminated C string returned by libSystem.
func readCStr(p *byte) string {
	if p == nil {
		return ""
	}
	var buf []byte
	for i := uintptr(0); ; i++ {
		c := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + i))
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return string(buf)
}

// runExtChild is the confined consumer. fd 3 carries the token; argv
// holds the target dir. The profile contains NO allowance for the dir:
// without the extension, every open below it must fail.
func runExtChild(dir string) {
	if err := extInit(); err != nil {
		fmt.Printf("child: ext symbols: %v\n", err)
		os.Exit(2)
	}
	spec := workerconf.DefaultSpec(64, "")
	rep, err := workerconf.Apply(spec)
	if err != nil {
		fmt.Printf("child: apply: %v (%+v)\n", err, rep)
		os.Exit(2)
	}
	// sanity: without the extension, create must fail
	if f, err := os.Create(filepath.Join(dir, "pre-token")); err == nil {
		_ = f.Close()
		fmt.Println("child: PRE-TOKEN CREATE SUCCEEDED — profile too weak, test invalid")
		os.Exit(2)
	}
	tok := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	f := os.NewFile(3, "tok")
	n, err := f.Read(buf)
	if err != nil {
		fmt.Printf("child: read token: %v\n", err)
		os.Exit(2)
	}
	tok = append(tok, buf[:n]...)
	token := string(tok[:len(tok)-1]) // strip \n
	h := sandboxExtensionConsume(cstr(token))
	if h < 0 {
		fmt.Printf("child: CONSUME FAILED (handle %d)\n", h)
		os.Exit(1)
	}
	out, err := os.Create(filepath.Join(dir, "via-extension"))
	switch {
	case err != nil:
		fmt.Printf("child: EXTENSION-CREATE: DENIED (%v)\n", err)
		os.Exit(1)
	default:
		_ = out.Close()
		fmt.Println("child: EXTENSION-CREATE: OK — extension lifted the path check")
	}
	sandboxExtensionRelease(h)
}

// runExtSpike is the unsandboxed issuer/parent.
func runExtSpike() {
	if err := extInit(); err != nil {
		fmt.Printf("extensions unavailable: %v\n", err)
		os.Exit(1)
	}
	base, err := os.MkdirTemp("", "seatbeltext-*")
	must("tempdir", err)
	defer func() { _ = os.RemoveAll(base) }()
	dir, err := filepath.EvalSymlinks(base) // issue against the canonical path
	must("canonicalize", err)

	exe, err := os.Executable()
	must("executable", err)
	rp, wp, err := os.Pipe()
	must("pipe", err)
	cmd := exec.Command(exe, "-ext-child", dir)
	cmd.ExtraFiles = []*os.File{wp} // child fd 3
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		must("start child", err)
	}
	_ = rp.Close()

	token := sandboxExtensionIssueFile(cstr(dir), 0)
	if token == nil {
		// Same class, targeted variant — last chance before declaring
		// the mechanism root-only.
		token = sandboxExtensionIssueFileToProcess(cstr(dir), 0, int32(cmd.Process.Pid))
		if token == nil {
			fmt.Println("ISSUE FAILED: sandbox_extension_issue_file and _to_process both returned nil")
			fmt.Println("\nextension verdict: ROOT-ONLY — extensions cannot solve hot-add for a user-space daemon; the restart-required refusal stands")
			_ = wp.Close()
			_ = cmd.Wait()
			os.Exit(1)
		}
		fmt.Println("issue_file failed but issue_file_to_process WORKED — using the targeted variant")
	}
	fmt.Printf("issued extension for %s\n", dir)
	if _, err := wp.WriteString(readCStr(token) + "\n"); err != nil {
		must("send token", err)
	}
	_ = wp.Close()
	err = cmd.Wait()
	if err != nil {
		fmt.Printf("\nextension verdict: CHILD FAILED (%v) — sandbox extensions do NOT solve hot-add; keep the restart-required refusal\n", err)
		os.Exit(1)
	}
	fmt.Println("\nextension verdict: WORKS — wire issue/consume into share hot-add (M2.5)")
}

func isExtChild() bool { return len(os.Args) > 2 && os.Args[1] == "-ext-child" }
func isExtSpike() bool { return len(os.Args) > 1 && os.Args[1] == "-extensions" }
