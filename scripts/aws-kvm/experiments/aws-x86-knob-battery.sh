#!/bin/bash
set +e
cd /opt/gantry || exit 1
G=./gantry-linux-amd64-kvm-pv
K=gantry-kernel-x86_64
variants=(base acpi numa mce power combined allocoff)
extra_base=''
extra_acpi='acpi=off'
extra_numa='numa=off'
extra_mce='mce=off'
extra_power='intel_pstate=disable cpuidle.off=1'
extra_combined='acpi=off numa=off mce=off intel_pstate=disable cpuidle.off=1'
extra_allocoff='init_on_alloc=0'
printf 'variant\trun\trc\tvcpu_ms\tmmio_ms\troot_ms\tvsock_ms\tready_ms\tvcpu_to_ready_ms\n'
for run in 1 2 3 4 5; do
  shift=$((run-1))
  for oi in 0 1 2 3 4 5 6; do
    idx=$(((oi+shift)%7)); v=${variants[$idx]}; eval "extra=\$extra_$v"
    n=ab-$v-$run
    $G stop "$n" >/dev/null 2>&1 || true
    rm -rf "/tmp/.gantry/sandboxes/$n"
    GANTRY_BOOT_TIMING=1 GANTRY_EXTRA_CMDLINE="$extra" timeout 30 $G start "$n" \
      -kernel "$K" -rootfs nerdbox-rootfs-x86_64.erofs \
      -image debian-bookworm-amd64.erofs -cpus 1 -mem 512 -rw=false \
      -net=false -process-isolation=off >/tmp/$n.out 2>&1
    rc=$?; log=/tmp/.gantry/sandboxes/$n/daemon.log
    vcpu=$(awk '/guest vCPU entered KVM/{print $(NF-6);exit}' "$log")
    mmio=$(awk '/guest first virtio-mmio/{print $(NF-6);exit}' "$log")
    root=$(awk '/guest first root-block/{print $(NF-6);exit}' "$log")
    vsock=$(awk '/guest first vsock/{print $(NF-6);exit}' "$log")
    ready=$(awk '/guest RPC connected/{print $(NF-1);exit}' "$log")
    delta=$(awk -v a="$vcpu" -v b="$ready" 'BEGIN{if(a!=""&&b!="")printf "%.3f",b-a;else printf "NA"}')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$run" "$rc" "${vcpu:-NA}" "${mmio:-NA}" "${root:-NA}" "${vsock:-NA}" "${ready:-NA}" "$delta"
    $G stop "$n" >/dev/null 2>&1 || true
  done
done
