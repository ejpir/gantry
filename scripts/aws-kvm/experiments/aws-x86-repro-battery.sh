#!/bin/bash
set +e
cd /opt/gantry||exit 1
G=./gantry-linux-amd64-kvm-pv2;K=gantry-kernel-x86_64-slim
variants=(repro quiet stock);r_repro=nerdbox-rootfs-x86_64-repro.erofs;r_quiet=nerdbox-rootfs-x86_64-quiet.erofs;r_stock=nerdbox-rootfs-x86_64.erofs
printf 'variant\trun\trc\tvcpu_to_mmio\tvcpu_to_root\tvcpu_to_vsock\tvcpu_to_ready\tconsole_bytes\n'
for run in 1 2 3 4 5 6 7;do shift=$((run%3));for oi in 0 1 2;do idx=$(((oi+shift)%3));v=${variants[$idx]};eval "r=\$r_$v";n=repro-$v-$run;$G delete $n >/dev/null 2>&1||true;taskset -c 0 env GANTRY_BOOT_TIMING=1 timeout 40 $G start $n -kernel $K -rootfs $r -image debian-bookworm-amd64.erofs -cpus 1 -mem 512 -rw=false -net=false -process-isolation=off >/tmp/$n 2>&1;rc=$?;L=/tmp/.gantry/sandboxes/$n/daemon.log;C=/tmp/.gantry/sandboxes/$n/console.log;bytes=$(wc -c <$C);awk -v q=$v -v x=$run -v rc=$rc -v b=$bytes '/guest vCPU entered KVM/{v=$(NF-6)}/guest first virtio-mmio/{m=$(NF-6)}/guest first root-block/{r=$(NF-6)}/guest first vsock/{s=$(NF-6)}/guest RPC connected/{d=$(NF-1)}END{printf "%s\t%s\t%s\t%.3f\t%.3f\t%.3f\t%.3f\t%s\n",q,x,rc,m-v,r-v,s-v,d-v,b}' $L;$G stop $n >/dev/null 2>&1||true;done;done
