# AWS KVM field tests

This directory contains the reproducible Linux KVM test environment for both
x86_64 and ARM64. It creates or reuses Amazon Linux 2023 `.metal` instances,
stages Gantry and guest assets in S3, and drives the instances through Systems
Manager (SSM). No inbound port or SSH key is required.

For the Windows Server/WHPX battery, use
[`../aws-whpx/README.md`](../aws-whpx/README.md). The detailed Linux test notes
and historical field results are in
[`../../docs/aws-kvm-test.md`](../../docs/aws-kvm-test.md).

## Prerequisites

- AWS CLI and Python 3 with `boto3`.
- Go, plus the local guest artifacts expected by `stage-assets.sh`.
- AWS credentials exported in the environment; never add them to this repo.
- A subnet id in the target VPC and permission to manage EC2, S3, IAM, SSM,
  security groups, and VPC endpoints.
- A subnet route to the destinations exercised by the network tests. The S3
  and SSM VPC endpoints created here do not themselves provide general
  Internet access.

The scripts default to `eu-west-1`, `c5.metal`, and bucket
`gantry-kvm-test-<account-id>`. Override these with `REGION`, `INSTANCE_TYPE`,
and `BUCKET`.

For routine x86_64 acceptance, the repository-level orchestrator builds and
stages the current curated Dev Containers image, starts the reusable Linux KVM
and Windows WHPX hosts, waits for SSM, tests real checksummed self-updates on
disposable binaries, runs every maintained field battery, and stops both
instances on exit:

```sh
source ~/keys
sh scripts/aws-e2e-validation.sh
```

Set `GANTRY_KEEP_INSTANCES=1` to leave both hosts running for investigation.
Instance IDs and the bucket can be overridden with `GANTRY_LINUX_IID`,
`GANTRY_WINDOWS_IID`, and `GANTRY_TEST_BUCKET`. The orchestrator needs a Docker-
compatible builder for the x86-64 curated image; set `GANTRY_TEST_IDE_IMAGE` to
an already-built EROFS image to skip that build.

On Apple-silicon macOS, the same entry point can run the local HVF manager and
a broad functional battery without loading AWS credentials or touching EC2. It
covers crun/runsc, lifecycle and revisioned resource configuration, OCI
pull/import/export/prune, shares, live ports and network policy, secrets and
OAuth custody, MCP, verified worker confinement, SSH/Dev Containers, and large
directories:

```sh
sh scripts/aws-e2e-validation.sh macos
```

It builds and ad-hoc signs the current host and guest-helper binaries. Existing
arm64 kernel, rootfs, and curated IDE assets are reused from `artifacts/`;
missing release assets are downloaded and a missing curated image is built.
Set `GANTRY_SKIP_DEVCONTAINERS=1` to skip only the curated-image SSH/Dev
Containers and large-directory checks; the core runtime, networking,
credentials, MCP, confinement, and manager batteries still run. The macOS
orchestrator skips the two direct-public-egress assertions when a socket probe
confirms that host policy permits Internet access only through a proxy; set
`GANTRY_TEST_PUBLIC_EGRESS=required` to force those assertions.

## Quick start

Run from the repository root:

```sh
source ~/keys

# Create/reuse the bucket, IAM profile, VPC endpoints, security groups,
# and AL2023 metal instance. Record the instance id printed at the end.
SUBNET_ID=subnet-xxxxxxxx sh scripts/aws-kvm/infra-up.sh
export GANTRY_TEST_IID=i-xxxxxxxxxxxxxxxxx

# Build and upload the Linux binary, kernel, rootfs, image, and rw layer.
sh scripts/aws-kvm/stage-assets.sh

# Run the crun/runsc, networking, shares, OCI-cache, and secrets battery.
sh scripts/aws-kvm/run-tests.sh

# Verify required-mode worker confinement on real KVM.
python3 scripts/aws-kvm/ssm.py \
  scripts/aws-kvm/confinement-battery.sh 900

# Stop billable compute and remove the billable SSM interface endpoints.
sh scripts/aws-kvm/infra-down.sh
```

`run-tests.sh` also expects `alpine-store.tar.gz` in the staging bucket for
its offline OCI-cache tests. If it is absent, stage the prepared store archive
before running the full battery or expect that section to fail.

## Script map

| Script | Purpose |
|---|---|
| `infra-up.sh` | Idempotently create/reuse the S3 bucket, IAM profile, VPC endpoints, security groups, and test instance. |
| `stage-assets.sh` | Cross-build `gantry-linux-amd64` and upload the standard test assets. |
| `run-tests.sh` | Upload a fresh x86_64 binary, populate `/opt/gantry`, and run `test-battery.sh`. |
| `run-tests-arm64.sh` | Upload current ARM64 binaries and boot assets, then run the maintained confinement/share/MCP battery on Graviton. |
| `test-battery.sh` | Exercise x86_64 crun, runsc, DNS/egress, concurrency, shares, cached OCI images, secrets, and OAuth custody. |
| `ssh-devcontainers-validation.sh` | Exercise direct and managed SSH, SFTP, asynchronous helper readiness, nested Podman, and stop/resume state handling. |
| `directory-validation.sh` | Exercise large shared-directory scans and host/guest coherence. |
| `self-update-validation.sh` | Verify a disposable tagged binary updates in place from a checksummed GitHub release. |
| `confinement-battery.sh` | Require split network/VMM workers and verify namespaces, private root, seccomp, shares, and egress. |
| `ssm.py` | Submit a shell script or one command through `AWS-RunShellScript` and wait for its result. |
| `infra-down.sh` | Stop or terminate the instance and optionally remove the SSM interface endpoints. |
| `infra-up-arm64.sh` | ARM wrapper selecting the `gantry-kvm-test-arm64` tag, AL2023 ARM64 AMI, and `c7g.metal`. |
| `infra-down-arm64.sh` | Stop/terminate the dedicated ARM host without matching the x86 tag. |

One-off boot, kernel, compression, and scaling probes are retained under
[`experiments/`](experiments/README.md).

## ARM64 / Graviton host

The exact ARM64 field batteries were preserved from `/tmp` under
[`experiments/`](experiments/README.md); the retained files are byte-for-byte
identical to the original `aws-arm-*.sh` scripts. They cover the KVM UAPI and
register probes, deferred SMP, 1/2/4/8-vCPU scaling, functional 8-vCPU exec,
and final timing collection.

Create or reuse the dedicated ARM host without colliding with the x86
`gantry-kvm-test` tag, then validate the current source tree:

```sh
source ~/keys
SUBNET_ID=subnet-xxxxxxxx sh scripts/aws-kvm/infra-up-arm64.sh
export GANTRY_TEST_IID=i-xxxxxxxxxxxxxxxxx

sh scripts/aws-kvm/run-tests-arm64.sh 1200

sh scripts/aws-kvm/infra-down-arm64.sh
```

The ARM runner exercises required split-worker confinement, egress, live and
boot shares, `FUSE_SYNCFS`, MCP helper delivery and proxying, and worker-death
degradation with the freshly built binary and guest helper. It expects
`ubuntu-arm64.erofs` in the staging bucket; the runner stages the remaining
current assets.

The historical ARM performance and SMP experiments can still be replayed with
`scripts/aws-kvm/experiments/aws-arm-final-battery.sh`. Those experiments
expect their named provenance assets to be present in
`/opt/gantry`, notably `gantry-linux-arm64-kvm-fixed`,
`gantry-kernel-arm64-deferred-smp`, `nerdbox-rootfs-arm64.erofs`, and
`ubuntu-arm64.erofs`. Their README lists the variants. Keep those names when
restaging so the scripts remain exact replays; they are historical experiment
batteries, not aliases for the current generic x86 battery.

## Running commands directly

```sh
python3 scripts/aws-kvm/ssm.py -c 'uname -a; ls -l /dev/kvm'
python3 scripts/aws-kvm/ssm.py scripts/aws-kvm/confinement-battery.sh 900
python3 scripts/aws-kvm/ssm.py i-xxxxxxxxxxxxxxxxx -c 'tail -80 /opt/gantry/test.log'
```

`ssm.py` prepends `set -e`. A replay script containing expected failures
should start with `set +e` and perform its own result accounting.

## Cost and cleanup

`.metal` instances and the three SSM interface endpoints are billable while
provisioned. The default cleanup stops the instance and deletes the interface
endpoints while retaining the bucket, IAM objects, security groups, and free
S3 gateway endpoint:

```sh
sh scripts/aws-kvm/infra-down.sh
sh scripts/aws-kvm/infra-down.sh --terminate
sh scripts/aws-kvm/infra-down.sh --keep-vpce
```

Use `--terminate` when the host state is no longer needed. Current AWS pricing
varies by region, so confirm costs in the account rather than relying on old
figures in test logs.

## Common failures

- **SSM never becomes online:** verify endpoint private DNS, endpoint security
  group ingress on TCP/443, the instance profile, and instance egress.
- **S3 downloads fail:** confirm the gateway endpoint/route table and rerun;
  the scripts retry transient `curl` failures.
- **DNS or Internet checks fail:** the SSM/S3 endpoints are healthy but the
  subnet may still lack NAT, proxy, or routed Internet egress.
- **Tests use an old binary:** stop existing sandboxes after replacing the
  executable. `run-tests.sh` does this before its atomic binary swap.
- **AWS reports `ExpiredToken`:** refresh the exported session credentials and
  rerun the command; no credential is stored by these scripts.
