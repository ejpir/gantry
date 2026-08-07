# Security Policy

gantry is a sandbox: its whole purpose is to run untrusted workloads inside
a VM boundary. We take bugs in that boundary seriously.

## Reporting a Vulnerability

**Please do not open a public issue for security reports.**

Preferred: use GitHub's private vulnerability reporting on this repository
(*Security* tab → *Advisories* → *Report a vulnerability*). If that is
unavailable, email the maintainer address listed in recent commit metadata.

Include: the affected version or commit, host OS/arch, guest type
(kernel/rootfs or imported container), a description of the boundary
crossed, and — if you have one — a reproducer or PoC. Exploit code is
welcome; we would rather see it than guess.

You can expect an acknowledgement within a few days and a candid
assessment of severity and fix timeline. We will credit reporters in the
fix commit/advisory unless you ask us not to.

## Scope

In scope — things we consider security bugs and will fix:

- **Guest → host escapes**: any path by which guest code (which has
  CAP_NET_RAW, CAP_SYS_ADMIN inside its namespaces, and root on the guest
  kernel) can execute code on, or read/write memory of, the host process
  or host kernel. This includes the virtio device implementations
  (blk, net, fs, vsock, rng, console), the guest agent RPC surface, and
  the kernel/initramfs we ship.
- **Share confinement bypasses**: accessing host paths outside the
  exported roots, following symlinks across the boundary, TOCTOU tricks
  against the pinned-root walk, or writing through a read-only export.
- **Network-policy bypasses**: evading the egress rules or DNS allowlist
  (fragmentation, segmentation, tunneling), or reaching the host/LAN
  without `allowLocal`.
- **Secrets handling**: host secrets reaching the guest beyond their
  declared scope, or leaking into logs/manifests/disk state.
- **Host-side privilege issues**: the control socket, state directory, or
  asset download/verification path enabling cross-user or privilege-
  escalating access on the host.

Out of scope — known, accepted properties of the design:

- Attacks that require host root or physical access to the host.
- Attacks by the host user against their own sandboxes: the trust domain
  is the user account (same-UID processes can already ptrace the VMM,
  read the sandbox directory, and connect to the control socket).
- Denial of service *by* a sandbox against its own resources (CPU/memory
  limits are best-effort, not hard isolation against a hostile guest
  burning its own allocation), except where the guest can exhaust
  **host-side** resources — that is in scope.
- Vulnerabilities in vendored or third-party code (report upstream; still
  tell us if our integration is the problem).
- The experimental Windows/WHPX backend (fix best-effort).

## Supported Versions

Only the latest release receives security fixes. There is no long-term
support line while the project is pre-1.0; the fix is "upgrade".

## Hardening Notes

The deliberate security posture of the codebase is documented in
`docs/hardening-audit.md` (guest/kernel hardening, asset verification,
share confinement model). When in doubt about whether something is a bug
or a documented trade-off, check there first — and if the documentation
and the code disagree, that disagreement itself is worth a report.
