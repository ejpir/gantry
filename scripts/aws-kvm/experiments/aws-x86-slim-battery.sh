#!/bin/bash
set +e
cd /opt/gantry || exit 1
G=./gantry-linux-amd64-kvm-pv
variants=(full slim)
k_full=gantry-kernel-x86_64
k_slim=gantry-kernel-x86_64-slim
printf 'variant\tcpus\trun\trc\tvcpu_ms\tmmio_ms\troot_ms\tvsock_ms\tready_ms\tvcpu_to_ready_ms\n'
for run in 1 2 3 4 5 6 7; do
 for cpu in 1 8;do
  shift=$(((run+cpu)%2))
  for oi in 0 1;do idx=$(((oi+shift)%2));v=${variants[$idx]};eval "k=\$k_$v";n=ks-$v-$cpu-$run
   $G stop "$n" >/dev/null 2>&1||true;rm -rf /tmp/.gantry/sandboxes/$n
   GANTRY_BOOT_TIMING=1 timeout 30 $G start "$n" -kernel "$k" -rootfs nerdbox-rootfs-x86_64.erofs -image debian-bookworm-amd64.erofs -cpus $cpu -mem 512 -rw=false -net=false -process-isolation=off >/tmp/$n.out 2>&1;rc=$?;log=/tmp/.gantry/sandboxes/$n/daemon.log
   vals=$(awk '/guest vCPU entered KVM/{v=$(NF-6)}/guest first virtio-mmio/{m=$(NF-6)}/guest first root-block/{r=$(NF-6)}/guest first vsock/{s=$(NF-6)}/guest RPC connected/{d=$(NF-1)}END{if(v!=""&&d!="")printf "%s\t%s\t%s\t%s\t%s\t%.3f",v,m,r,s,d,d-v;else print "NA\tNA\tNA\tNA\tNA\tNA"}' "$log")
   printf '%s\t%s\t%s\t%s\t%s\n' "$v" "$cpu" "$run" "$rc" "$vals";$G stop "$n" >/dev/null 2>&1||true
  done
 done
done
