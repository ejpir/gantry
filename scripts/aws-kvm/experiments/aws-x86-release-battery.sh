#!/bin/bash
set +e
cd /opt/gantry || exit 1
G=./gantry-linux-amd64-x86-final
K=./gantry-kernel-x86_64-final
R=./nerdbox-rootfs-x86_64-repro.erofs
I=./debian-bookworm-amd64.erofs
printf 'binary_sha256='; sha256sum "$G"|awk '{print $1}'
printf 'kernel_sha256='; sha256sum "$K"|awk '{print $1}'
printf 'rootfs_sha256='; sha256sum "$R"|awk '{print $1}'
printf 'cpus\tnet\trun\trc\tcli_ms\tvcpu_ms\tmmio_ms\troot_ms\tvsock_ms\tready_ms\tvcpu_to_ready_ms\tconsole_bytes\n'
P=0;F=0
for run in 1 2 3 4 5 6 7; do
 for cpu in 1 8; do
  for net in false true; do
   n=release2-$cpu-$net-$run;s=/tmp/.gantry/sandboxes/$n
   $G delete $n >/dev/null 2>&1||true
   t0=$(date +%s%N)
   taskset -c 0 env GANTRY_BOOT_TIMING=1 timeout 40 $G start $n -kernel $K -rootfs $R -image $I -cpus $cpu -mem 512 -rw=false -net=$net -process-isolation=off >/tmp/$n.out 2>&1
   rc=$?;t1=$(date +%s%N);cli=$(awk -v x=$((t1-t0)) 'BEGIN{printf "%.3f",x/1e6}')
   vals=$(awk '/guest vCPU entered KVM/{v=$(NF-6)}/guest first virtio-mmio/{m=$(NF-6)}/guest first root-block/{r=$(NF-6)}/guest first vsock/{s=$(NF-6)}/guest RPC connected/{d=$(NF-1)}END{if(v!=""&&d!="")printf "%s\t%s\t%s\t%s\t%s\t%.3f",v,m,r,s,d,d-v;else print "NA\tNA\tNA\tNA\tNA\tNA"}' $s/daemon.log)
   bytes=$(wc -c <$s/console.log 2>/dev/null)
   printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' $cpu $net $run $rc $cli "$vals" "${bytes:-NA}"
   if [ $rc -eq 0 ];then P=$((P+1));else F=$((F+1));fi
   $G stop $n >/dev/null 2>&1||true
  done
 done
done
# Functional 8-vCPU/network check in writable mode.
n=release2-functional;$G delete $n >/dev/null 2>&1||true
timeout 40 $G start $n -kernel $K -rootfs $R -image $I -cpus 8 -mem 512 -net=true -process-isolation=off >/tmp/$n.out 2>&1;src=$?
sleep 1
printf 'nproc; grep -c "^processor" /proc/cpuinfo; cat /sys/devices/system/cpu/online; getent hosts deb.debian.org; echo X86-RELEASE-OK\nexit\n' | timeout 90 $G exec $n >/tmp/$n.exec 2>&1;erc=$?
echo "functional_start_rc=$src functional_exec_rc=$erc";grep -aE '^[0-9]+$|^[0-9,-]+$|X86-RELEASE-OK|debian.org' /tmp/$n.exec
[ $src -eq 0 ] && [ $erc -eq 0 ] && grep -q X86-RELEASE-OK /tmp/$n.exec && P=$((P+1)) || F=$((F+1))
$G stop $n >/dev/null 2>&1||true
echo "RESULT: $P passed, $F failed";[ $F -eq 0 ]
