#!/usr/bin/env python3
"""kernel-boot-probe.py — instrument the guest kernel's ID-register reads.

Boot on Apple silicon spends ~136 ms inside mm_core_init() with the guest
looping on __read_sysreg_by_encoding(SYS_ID_AA64ISAR0_EL1); each of those
reads traps to EL2 for Hypervisor.framework to emulate (docs/boot-timing.md).
Host-side sampling can see WHERE the guest is but not how often it gets there
or who called it, and both answers live inside the guest.

This adds three things to an extracted kernel tree:

  * counters for every by-encoding ID read, and for ID_AA64ISAR0_EL1 alone;
  * a one-shot dump_stack() once the count crosses a threshold, which names
    the caller outright;
  * counter readouts at each step of mm_core_init(), so the reads can be
    attributed to a phase. Timing comes for free — gantry host-stamps every
    console line while the boot timeline is live, so these printks are
    already on the same clock as the exit trace.

With --fix-rngcap it also applies the fix those probes found: arm64 asks
"does this CPU have RNDR?" through this_cpu_has_cap() on every random word,
which is uncached BY DESIGN (it answers for the current CPU, so it re-reads
the ID register). SLAB freelist randomisation calls it once per slab object
— 141 408 times inside kmem_cache_init on a 512 MiB guest — and at ~0.96 us
per trapped read that is the whole 136 ms. Caching the answer keeps
CONFIG_SLAB_FREELIST_RANDOM, unlike the alternative of switching it off.

Idempotent: re-running against an already-patched tree is a no-op, so a
reused WORK tree does not accumulate probes. Any missing anchor is fatal —
a half-instrumented kernel would produce numbers that quietly mean nothing.

  usage: kernel-boot-probe.py <kernel-source-root> [--dump-at N]
                              [--fix-rngcap] [--skip-probe]
"""

import pathlib
import re
import sys

MARKER = "gantry-probe"

CPUFEATURE_DECLS = """
/* gantry-probe: ID-register reads trap to EL2 under Hypervisor.framework;
 * count them so guest-side cost can be attributed. Not upstream material. */
u64 gantry_idreg_reads;
u64 gantry_idreg_isar0;
"""

CPUFEATURE_COUNT = """	/* gantry-probe */
	gantry_idreg_reads++;
	if (sys_id == SYS_ID_AA64ISAR0_EL1)
		gantry_idreg_isar0++;
	if (gantry_idreg_reads == {threshold})
		dump_stack();

"""

MM_INIT_DECLS = """
/* gantry-probe */
#ifdef CONFIG_ARM64
extern u64 gantry_idreg_reads, gantry_idreg_isar0;
#define GANTRY_PROBE(label) \\
	pr_info("gantry-probe: %s idreads=%llu isar0=%llu\\n", \\
		label, gantry_idreg_reads, gantry_idreg_isar0)
#else
#define GANTRY_PROBE(label) do { } while (0)
#endif
"""

# Statements inside mm_core_init() to report after. The first and last are
# the two printks that bracket the measured window; the rest are whatever
# this kernel actually has between them.
MM_INIT_ANCHORS = [
    "report_meminit();",
    "kmsan_init_shadow();",
    "stack_depot_early_init();",
    "mem_init();",
    "mem_init_print_info();",
    "kmem_cache_init();",
]
MM_INIT_REQUIRED = {"report_meminit();", "kmem_cache_init();"}


RNGCAP_CALL = "this_cpu_has_cap(ARM64_HAS_RNG)"

RNGCAP_HELPER = """
/* gantry-probe: this_cpu_has_cap() is uncached by design — it re-reads
 * ID_AA64ISAR0_EL1 to answer for the CURRENT cpu. Under Hypervisor.framework
 * that read traps to EL2 (~0.96 us), and SLAB freelist randomisation asks
 * once per slab object: 141408 reads inside kmem_cache_init, ~136 ms of boot.
 * Gantry exposes the same RNDR capability to every virtual CPU. Cache the
 * early answer; after arm64 finalizes system capabilities, the surrounding
 * upstream helper switches to its patched-alternative system-wide check. */
static inline bool gantry_cached_has_rng(void)
{
	static int cached = -1;

	if (unlikely(cached < 0))
		cached = this_cpu_has_cap(ARM64_HAS_RNG);
	return cached > 0;
}
"""


def fail(message):
    sys.exit("kernel-boot-probe: " + message)


def patch_cpufeature(root, threshold):
    path = root / "arch/arm64/kernel/cpufeature.c"
    text = path.read_text()
    if MARKER in text:
        return False
    signature = "u64 __read_sysreg_by_encoding(u32 sys_id)\n{"
    at = text.find(signature)
    if at < 0:
        fail(f"{path}: no __read_sysreg_by_encoding(u32 sys_id) definition")
    # The counters must precede the function; the increment goes at the top
    # of its body, before the switch that reads the register.
    body = text.index("\n", at + len(signature)) + 1
    switch = text.find("\tswitch (sys_id) {", body)
    if switch < 0:
        fail(f"{path}: __read_sysreg_by_encoding has no switch (sys_id)")
    text = (text[:switch]
            + CPUFEATURE_COUNT.format(threshold=threshold)
            + text[switch:])
    text = text[:at] + CPUFEATURE_DECLS.lstrip("\n") + "\n" + text[at:]
    path.write_text(text)
    return True


def patch_mm_init(root):
    path = root / "mm/mm_init.c"
    text = path.read_text()
    if MARKER in text:
        return False, []
    signature = "void __init mm_core_init(void)\n{"
    at = text.find(signature)
    if at < 0:
        fail(f"{path}: no mm_core_init(void) definition")
    end = text.find("\n}\n", at)
    if end < 0:
        fail(f"{path}: mm_core_init(void) has no closing brace")
    # Keep the final statement's newline inside the body, or the last call in
    # the function can never match an anchor.
    end += 1

    body, probed = text[at:end], []
    for anchor in MM_INIT_ANCHORS:
        found = body.find("\t" + anchor + "\n")
        if found < 0:
            continue
        after = found + len("\t" + anchor + "\n")
        body = (body[:after]
                + f'\tGANTRY_PROBE("after {anchor[:-3]}");\n'
                + body[after:])
        probed.append(anchor)
    missing = MM_INIT_REQUIRED - set(probed)
    if missing:
        fail(f"{path}: mm_core_init lacks {', '.join(sorted(missing))} — "
             "the measured window is bounded by those two, so the probe "
             "would not describe it")

    text = text[:at] + body + text[end:]
    # Declarations go after the include block so the macro is in scope.
    includes = list(re.finditer(r"^#include .*$", text, re.M))
    if not includes:
        fail(f"{path}: no #include block")
    insert = includes[-1].end() + 1
    text = text[:insert] + MM_INIT_DECLS + text[insert:]
    path.write_text(text)
    return True, probed


def patch_rngcap(root):
    """Cache the RNDR capability answer on arm64's random path."""
    path = root / "arch/arm64/include/asm/archrandom.h"
    if not path.is_file():
        fail(f"{path}: not found — cannot apply the RNDR capability fix")
    text = path.read_text()
    if MARKER in text:
        return 0
    uses = text.count(RNGCAP_CALL)
    if not uses:
        fail(f"{path}: no {RNGCAP_CALL} — this kernel does not take the "
             "uncached path the fix targets, so applying it would be a no-op "
             "hiding a wrong assumption")
    # Rewrite the call sites BEFORE inserting the helper: the helper body
    # contains the very call being replaced, and rewriting it too would make
    # it call itself — infinite recursion that compiles cleanly and hangs the
    # guest at boot.
    text = text.replace(RNGCAP_CALL, "gantry_cached_has_rng()")
    # The helper must precede its callers; the first user is far enough into
    # the header that the includes are already in scope.
    first = text.index("gantry_cached_has_rng()")
    line = text.rfind("\nstatic ", 0, first)
    if line < 0:
        fail(f"{path}: no function definition precedes {RNGCAP_CALL}")
    text = (text[:line + 1] + RNGCAP_HELPER.lstrip("\n") + "\n" + text[line + 1:])
    path.write_text(text)
    return uses


def main():
    args, root, threshold = sys.argv[1:], None, "1000"
    fix_rngcap = skip_probe = False
    while args:
        arg = args.pop(0)
        if arg == "--fix-rngcap":
            fix_rngcap = True
        elif arg == "--skip-probe":
            skip_probe = True
        elif arg == "--dump-at":
            if not args:
                fail("--dump-at needs a value")
            threshold = args.pop(0)
        elif arg.startswith("-") or root is not None:
            fail(f"usage: kernel-boot-probe.py <kernel-source-root> "
                 f"[--dump-at N] [--fix-rngcap] [--skip-probe] (got {arg!r})")
        else:
            root = pathlib.Path(arg)
    if root is None:
        fail("usage: kernel-boot-probe.py <kernel-source-root> "
             "[--dump-at N] [--fix-rngcap] [--skip-probe]")
    if not threshold.isdigit() or int(threshold) < 1:
        fail(f"--dump-at must be a positive integer, got {threshold!r}")
    if not (root / "Makefile").is_file():
        fail(f"{root} is not a kernel source tree")

    changed = False
    if not skip_probe:
        counted = patch_cpufeature(root, threshold)
        probed_mm, probes = patch_mm_init(root)
        if counted or probed_mm:
            changed = True
            print(f"kernel-boot-probe: counting ID-register reads, "
                  f"dump_stack at #{threshold}")
            print("kernel-boot-probe: mm_core_init probes after " +
                  ", ".join(p[:-3] for p in probes))
    if fix_rngcap:
        uses = patch_rngcap(root)
        if uses:
            changed = True
            print(f"kernel-boot-probe: cached the RNDR capability check "
                  f"({uses} call site{'s' if uses > 1 else ''})")
    if not changed:
        print("kernel-boot-probe: already instrumented")


main()
