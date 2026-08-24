# Windows WHPX field replay

These files preserve the EC2 Windows Server 2022 acceptance run for the WHPX
backend. The replay validates the AppContainer device VMM plus narrow WHPX
broker, shared-memory exit mailboxes, Job boundaries, guest exec and writable
layer, live and persistent NTFS shares, DNS → TCP → TLS → HTTP using the staged
`netprobe` image, host-bound secrets, OAuth token custody, MCP policy, audit
behavior, and large shared directories.

From the repository root:

```sh
source ~/keys
GANTRY_TEST_IID=i-xxxxxxxxxxxxxxxxx \
GANTRY_TEST_BUCKET=gantry-kvm-test-ACCOUNT \
sh scripts/aws-whpx/replay.sh
```

The defaults match the field host layout under `C:\gantry` and use the saved
`plain` sandbox. Override paths for another host with the environment variables
read at the top of `field-validation.ps1`, notably `GANTRY_TEST_ROOT`,
`GANTRY_HOME`, `GANTRY_TEST_SANDBOX`, `GANTRY_TEST_KERNEL`,
`GANTRY_TEST_ROOTFS`, and `GANTRY_TEST_NETPROBE_IMAGE`.

The instance needs SSM connectivity, WHPX enabled, outbound security-group
access, and the kernel/rootfs/netprobe assets already staged. No credential is
embedded in the scripts. The host helper builds fresh Windows host and Linux
guest-helper binaries, uploads them to S3, and gives the instance one-hour
presigned download URLs.

To start both reusable field hosts, run the Linux and Windows batteries, test a
real checksummed self-update on disposable binaries, and stop the instances on
exit, use the repository-level orchestrator:

```sh
source ~/keys
sh scripts/aws-e2e-validation.sh
```

Set `GANTRY_KEEP_INSTANCES=1` to leave both hosts running after a replay.

`boot-comparison.ps1` runs both implementations on that same Windows host. Its
QEMU side is deliberately and verifiably the `microvm` machine—
`-M microvm,kernel-irqchip=off,acpi=off -accel whpx`—with direct PVH kernel
boot and one virtio-mmio root disk. It records QEMU's first `vminitd` system
initialization log and Gantry's daemon-ready milestone separately because QEMU
has no Gantry vsock readiness device. Windows defaults to the
small-e820/virtio-mem path; set `GANTRY_TEST_VIRTIO_MEM=0` to benchmark the
legacy eager-memory layout. The default path reserves the configured address range, commits and maps
only the 512 MiB boot region before vCPU start, publishes readiness, and then
commits/maps and onlines the remainder asynchronously. Readiness therefore
means that guest RPC is usable, not that all configured RAM is online; the
high-memory validation polls `MemTotal` before running its memory-touch test.
Set `GANTRY_VIRTIO_MEM=0` when deliberately booting a custom kernel that lacks
built-in `CONFIG_VIRTIO_MEM` support.

Windows `auto` now expects `split-net+split-vmm`: the network report verifies
its capability-bearing AppContainer and fs-read/fs-write/exec denial, while the
VMM report verifies fs-read/fs-write/net-dial/exec denial and discloses the
separate Job-confined trusted WHPX broker. The field battery also boots
`required` and validates DNS/TCP/TLS/HTTP, plus an offline `-net=false`
`split-vmm` boot. Because Windows AppContainer network
isolation blocks host loopback, startup ports and loopback-allowing policies
fall back in `auto` and fail closed in `required`. Set
`GANTRY_WINDOWS_WHPX_BROKER=0` to exercise the older Job-only VMM compatibility
fallback; that fallback must report fs/net as unenforced rather than silently
claiming the AppContainer tier.
