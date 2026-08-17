# Windows WHPX field replay

These files preserve the EC2 Windows Server 2022 acceptance run for the WHPX
backend. The replay validates the split VMM process, Job Object boundary,
guest exec and writable layer, live and persistent NTFS shares, and DNS → TCP
→ TLS → HTTP using the staged `netprobe` image.

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
embedded in the scripts. The host helper builds a fresh Windows binary, uploads
it to S3, and gives the instance a one-hour presigned download URL.

`boot-comparison.ps1` runs both implementations on that same Windows host. Its
QEMU side is deliberately and verifiably the `microvm` machine—
`-M microvm,kernel-irqchip=off,acpi=off -accel whpx`—with direct PVH kernel
boot and one virtio-mmio root disk. It records QEMU's first `vminitd` system
initialization log and Gantry's daemon-ready milestone separately because QEMU
has no Gantry vsock readiness device. Set `GANTRY_TEST_VIRTIO_MEM=1` to
benchmark the opt-in small-e820/virtio-mem path with a compatible test kernel.
On Windows that path reserves the configured address range, commits and maps
only the 512 MiB boot region before vCPU start, publishes readiness, and then
commits/maps and onlines the remainder asynchronously. Readiness therefore
means that guest RPC is usable, not that all configured RAM is online; the
high-memory validation polls `MemTotal` before running its memory-touch test.
Do not enable `GANTRY_VIRTIO_MEM` with an older kernel that lacks built-in
`CONFIG_VIRTIO_MEM` support.

The replay intentionally treats Windows `auto` isolation as partial: it
requires `split-vmm` and an enforced process boundary, while the JSON report is
expected to describe filesystem and ambient-network confinement honestly.
`required` must continue to fail closed until those properties are enforced.
