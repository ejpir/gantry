# AWS KVM field experiments

These are the exact one-off SSM scripts retained from the arm64 KVM and x86
startup investigations. They expect assets to have already been staged in
`/opt/gantry` on the target metal instance. Run one from the repository root:

```sh
set -a; . "$HOME/keys"; set +a
python3 scripts/aws-kvm/ssm.py i-INSTANCE \
  scripts/aws-kvm/experiments/aws-x86-final-battery.sh 900
```

All benchmark scripts start with `set +e`, as required by `ssm.py`, and clean
up the sandboxes they create. File names inside each script record the exact
experimental binaries, kernels, and root filesystems it used; either stage
those names or update the variables at the top before reuse.

## Scripts

- `aws-kvm-deferred-smp-test.sh`: original cross-architecture deferred-SMP
  field battery.
- `aws-arm-fixed-scaling.sh`, `aws-arm-final-battery.sh`, and
  `aws-arm-final-metrics.sh`: arm64 KVM/FDT correction and scaling validation.
- `arm64-kvm-uapi-probe.sh`, `arm64-register-probe/main.go`, and
  `arm64-boot-probe/main.go`: the corrected arm64 KVM ioctl, core-register,
  and tiny-guest probes used to isolate the original backend failure. Copy a
  Go probe to an arm64 Linux host before `go run`; its build tag intentionally
  prevents accidental execution elsewhere.
- `aws-x86-deferred-smp-scaling.sh`: x86 deferred-SMP scaling validation.
- `aws-x86-knob-battery.sh`: interleaved x86 kernel-command-line experiments.
- `aws-x86-slim-battery.sh`: full versus slim x86 kernel comparison.
- `aws-x86-quiet-battery.sh`: stock versus quiet nerdbox rootfs comparison.
- `aws-x86-final-battery.sh`: early CPU/network matrix using the optimized
  KVM contract, slim kernel, and quiet rootfs.
- `aws-x86-repro-battery.sh`: stock, experimental, and source-reproduced quiet
  rootfs comparison.
- `aws-x86-release-battery.sh`: final seven-run CPU/network matrix plus an
  8-vCPU OCI/DNS functional check using the repository-built artifacts.
- `aws-x86-compress-battery.sh`: compressed versus uncompressed quiet rootfs.
- `aws-x86-runtime-battery.sh`: quiet, stock, and historical gVisor rootfs
  startup comparison.
- `aws-final-timing.sh`: historical cross-architecture timing sweep.

## Timing parsing

Current scripts parse the numeric `total` value from lines like:

```
boot-timing: guest vCPU entered KVM  91.068 ms total (vCPU + 0.000 ms)
```

The older `aws-final-timing.sh` instead reads `$(NF-4)`, which is the literal
word `total` in that format. Its `vcpu_ms` and derived values are invalid; the
script is kept verbatim as provenance and should be fixed before reuse.

AWS bare-metal runs showed occasional 80–100 ms host scheduling stalls even
with low load and no cgroup CPU quota. Use interleaved variants, at least seven
samples, retained logs, and medians. Treat vCPU-to-READY as guest startup;
CLI-to-READY also includes host management overhead.
