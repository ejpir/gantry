# kernel-hardening.sh — shared hardening config for Gantry's guest kernels.
#
# Sourced by mkkernel.sh (and its back-compat wrappers). The lists below
# harden the guest kernel against in-guest attackers (a container escape,
# a malicious workload, a confused agent). They are deliberately one-sided:
# everything here protects the guest kernel or other tenants of the same
# VM; the host boundary stays the hypervisor + the confined VMM process.
#
# Why not more (Lockdown, Landlock, BPF LSM, IPE)? In-guest LSM policy
# stacks add attack surface and maintenance for a layer that is already
# disposable: a guest-kernel compromise is contained by the VM boundary.
# We take the cheap, always-on memory-corruption and info-leak hardening
# instead. See docs/hardening-audit.md for the full comparison.

# Always-on hardening. Each symbol must survive olddefconfig — the verify
# step below fails the build otherwise.
GANTRY_HARDENING_ENABLES="
HARDENED_USERCOPY          # bounds-check copy_to/from_user against slab/stack
FORTIFY_SOURCE             # __builtin_object_size checks on copy/str/mem fns
INIT_ON_ALLOC_DEFAULT_ON   # zero heap/page allocations by default
INIT_ON_FREE_DEFAULT_ON    # poison freed memory (use-after-free mitigation)
SLAB_FREELIST_RANDOM       # randomize freelist order (heap-layout control)
SLAB_FREELIST_HARDENED     # freelist pointer obfuscation + double-free checks
SHUFFLE_PAGE_ALLOCATOR     # randomize page allocator freelists
DEBUG_LIST                 # linked-list corruption checks
BUG_ON_DATA_CORRUPTION     # corrupt kernel structures are fatal, not warned
STATIC_USERMODEHELPER      # no kernel-spawned helpers (core_pattern pipes etc)
SECURITY_DMESG_RESTRICT    # dmesg requires CAP_SYSLOG
SECURITY_YAMA                # ptrace_scope restrictions (LSM order already lists it)
BPF_UNPRIV_DEFAULT_OFF     # unprivileged eBPF off at boot (crun runs privileged)
RANDOMIZE_KSTACK_OFFSET_DEFAULT  # per-syscall kernel stack randomization
"

# Attack surface we never want in a guest. KEXEC is already absent from the
# nerdbox baseline; keep it out if a future baseline re-enables it. MODULES
# let guest root load arbitrary unsigned kernel code and undo most other
# hardening; every in-guest driver is built-in (=y), so modules buy nothing.
GANTRY_HARDENING_DISABLES="
KEXEC KEXEC_FILE           # no kexec from inside the guest
MODULES                    # no loadable modules (unsigned module = full bypass)
"

# Best-effort: kept when toolchain/hardware support exists, warned about
# otherwise (olddefconfig drops symbols whose dependencies are missing).
GANTRY_HARDENING_TRY="
ARM64_PTR_AUTH             # PAC: return-address signing (arm64 only)
ARM64_BTI                  # BTI: indirect-branch target validation (arm64 only)
"

# apply_kernel_hardening: run inside the kernel tree, after the baseline
# .config is in place and before olddefconfig.
apply_kernel_hardening() {
	for sym in $(printf '%s\n' "$GANTRY_HARDENING_ENABLES" | sed 's/#.*//'); do
		scripts/config --enable "$sym"
	done
	for sym in $(printf '%s\n' "$GANTRY_HARDENING_DISABLES" | sed 's/#.*//'); do
		scripts/config --disable "$sym"
	done
	for sym in $(printf '%s\n' "$GANTRY_HARDENING_TRY" | sed 's/#.*//'); do
		scripts/config --enable "$sym"
	done
}

# verify_kernel_hardening: run after olddefconfig. Critical symbols must be
# =y; best-effort symbols only warn.
verify_kernel_hardening() {
	missing=""
	for sym in $(printf '%s\n' "$GANTRY_HARDENING_ENABLES" | sed 's/#.*//'); do
		grep -q "^CONFIG_$sym=y" .config || missing="$missing $sym"
	done
	if [ -n "$missing" ]; then
		echo "hardening config failed to stick:$missing" >&2
		echo "check $PWD/.config against linux-$VERSION symbol names" >&2
		exit 1
	fi
	for sym in $(printf '%s\n' "$GANTRY_HARDENING_TRY" | sed 's/#.*//'); do
		grep -q "^CONFIG_$sym=y" .config || \
			echo "note: best-effort hardening $sym not available (toolchain/arch), continuing"
	done
	for sym in $(printf '%s\n' "$GANTRY_HARDENING_DISABLES" | sed 's/#.*//'); do
		if grep -q "^CONFIG_$sym=y" .config; then
			echo "hardening disable failed: CONFIG_$sym=y still present" >&2
			exit 1
		fi
	done
}
