#!/bin/bash
set +e
cd /opt/gantry||exit 1
G=./gantry-linux-amd64-kvm-pv2;K=gantry-kernel-x86_64-slim;R=nerdbox-rootfs-x86_64-quiet.erofs
printf 'cpus\tnet\trun\trc\tcli_ms\tvcpu_ms\tmmio_ms\troot_ms\tvsock_ms\tready_ms\tvcpu_to_ready_ms\n'
for run in 1 2 3 4 5 6 7;do for cpu in 1 8;do for net in false true;do n=final-$cpu-$net-$run;$G delete $n >/dev/null 2>&1||true;t0=$(date +%s%N);GANTRY_BOOT_TIMING=1 timeout 30 $G start $n -kernel $K -rootfs $R -image debian-bookworm-amd64.erofs -cpus $cpu -mem 512 -rw=false -net=$net -process-isolation=off >/tmp/$n.out 2>&1;rc=$?;t1=$(date +%s%N);cli=$(awk -v x=$((t1-t0)) 'BEGIN{printf "%.3f",x/1e6}');log=/tmp/.gantry/sandboxes/$n/daemon.log;vals=$(awk '/guest vCPU entered KVM/{v=$(NF-6)}/guest first virtio-mmio/{m=$(NF-6)}/guest first root-block/{r=$(NF-6)}/guest first vsock/{s=$(NF-6)}/guest RPC connected/{d=$(NF-1)}END{if(v!=""&&d!="")printf "%s\t%s\t%s\t%s\t%s\t%.3f",v,m,r,s,d,d-v;else print "NA\tNA\tNA\tNA\tNA\tNA"}' $log);printf '%s\t%s\t%s\t%s\t%s\t%s\n' $cpu $net $run $rc $cli "$vals";$G stop $n >/dev/null 2>&1||true;done;done;done
