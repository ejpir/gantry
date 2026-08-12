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

The replay intentionally treats Windows `auto` isolation as partial: it
requires `split-vmm` and an enforced process boundary, while the JSON report is
expected to describe filesystem and ambient-network confinement honestly.
`required` must continue to fail closed until those properties are enforced.
