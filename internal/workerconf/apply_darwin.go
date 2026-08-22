//go:build darwin

package workerconf

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

// sandbox_init_with_parameters applies a Seatbelt profile to the whole
// process. It lives in libSystem (the dyld shared cache); the SDK has
// marked it deprecated for years but Chrome/WebKit-class consumers keep
// it ABI-stable, and dlsym does not care about deprecation. It may be
// called at most once per process — the worker applies exactly once,
// after consuming its descriptor table and before hv_vm_create.
var sandboxInitWithParameters func(profile *byte, flags uint64, params uintptr, errbuf **byte) int32

func init() {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return // Apply reports the honest failure
	}
	sym, err := purego.Dlsym(lib, "sandbox_init_with_parameters")
	if err != nil {
		return
	}
	purego.RegisterFunc(&sandboxInitWithParameters, sym)
}

// Apply confines the worker via Seatbelt. HVF's hv_* calls are mach
// traps, which Seatbelt does not filter. Native confinement tests verify
// the profile on real hardware, so confinement installs before VMM setup
// exercises the hypervisor.
func Apply(spec Spec) (*Report, error) {
	if !validProfile(spec.Profile) {
		return nil, fmt.Errorf("workerconf: invalid syscall profile %d", spec.Profile)
	}
	if sandboxInitWithParameters == nil {
		rep := DisabledReport("darwin", "")
		rep.Notes = append(rep.Notes, "sandbox_init_with_parameters unavailable")
		return &rep, fmt.Errorf("seatbelt: symbol unavailable")
	}
	profile := buildSeatbeltProfile(spec)
	profileBytes := append([]byte(profile), 0)
	var errbuf *byte
	rc := sandboxInitWithParameters(&profileBytes[0], 0, 0, &errbuf)
	if rc != 0 {
		rep := DisabledReport("darwin", "")
		rep.Notes = append(rep.Notes, "seatbelt apply failed: "+goString(errbuf))
		return &rep, fmt.Errorf("seatbelt apply: %s", goString(errbuf))
	}
	rep := &Report{
		Platform: "darwin",
		Applied:  true,
		Notes:    []string{fmt.Sprintf("seatbelt profile v1 (%d bytes, %d path allowances)", len(profile), len(spec.FileAllow))},
	}
	return rep, nil
}

// goString reads a NUL-terminated C string; "unknown error" for nil.
func goString(p *byte) string {
	if p == nil {
		return "unknown error"
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
