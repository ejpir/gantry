// Package vmm boots and runs a guest virtual machine on the host's native
// hypervisor.
//
// The package has two roles, deliberately kept together in one package:
//
//   - Machine is the device model and guest-state owner: RAM, virtio cores,
//     the UART and (on x86) the legacy PC device cluster, MMIO and port-I/O
//     dispatch (handleMMIO/handleIO), the interrupt router, console
//     plumbing, and the boot timeline. Prepare builds it; Close tears it
//     down, joining the backend before releasing devices and RAM.
//   - The backend is the per-platform vCPU execution engine — KVM
//     (linux/amd64, linux/arm64), Hypervisor.framework (darwin), or WHPX
//     (windows). Build constraints select exactly one backend per platform;
//     each implements the unexported backend interface, and Run drives it.
//
// The dependency is bidirectional by design. Backends call into Machine for
// every guest exit (device dispatch, console output, boot milestones) and
// for their lifecycle interlock (beginRun/finishRun/adoptBackend, Close).
// In the other direction Machine never calls a backend directly: the
// backend publishes its interrupt-line callback into Machine's
// interruptRouter, which is disabled before native teardown.
//
// Keeping the backends in-package is a deliberate choice, not deferred
// cleanup. Extracting them would require a Machine-facing interface
// covering essentially the whole Machine struct (dispatch, memory layout,
// console, lifecycle, timing), and since exactly one backend compiles per
// platform, a package split would buy no compile-time or API-surface win.
// Where coupling can be narrowed cheaply it is: backend instrumentation
// flows through the small bootTracer interface rather than the concrete
// boot timeline.
//
// Public surface: Opts and Prepare construct a Machine, Run boots it on the
// platform backend, Close releases it. InjectVsockConn and RequestHotMemory
// are the runtime operations.
package vmm
