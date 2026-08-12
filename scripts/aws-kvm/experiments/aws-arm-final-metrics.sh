#!/bin/bash
set +e
cd /opt/gantry||exit 1
G=./gantry-linux-arm64-final;K=./gantry-kernel-arm64-deferred-smp;R=./nerdbox-rootfs-arm64.erofs;I=./ubuntu-arm64.erofs
P=0;F=0;ok(){ echo "PASS: $1";P=$((P+1));};bad(){ echo "FAIL: $1";F=$((F+1));}
echo -e 'cpus\trun\trc\tcli_ms\tprep_ms\tready_ms\tboots\tfailures'
for C in 1 2 4 8;do for X in 1 2 3;do N=arm-metric-c$C-r$X;S=/tmp/.gantry/sandboxes/$N;$G stop $N >/dev/null 2>&1||true;rm -rf $S;A=$(date +%s%N);GANTRY_BOOT_TIMING=1 timeout 30 $G start $N -kernel $K -rootfs $R -image $I -cpus $C -mem 512 -rw=false -net=false -process-isolation=off >/tmp/$N.out 2>&1;RC=$?;B=$(date +%s%N);sleep 1;CLI=$(awk -v n=$((B-A)) 'BEGIN{printf "%.3f",n/1e6}');PREP=$(grep -m1 'machine prepared' $S/daemon.log|awk '{print $(NF-1)}');READY=$(grep -m1 'guest RPC connected' $S/daemon.log|awk '{print $(NF-1)}');BOOTS=$(grep -c 'Booted secondary processor' $S/console.log);BAD=$(grep -cE 'failed to online|failed to boot|Kernel panic' $S/console.log);echo -e "$C\t$X\t$RC\t$CLI\t$PREP\t$READY\t$BOOTS\t$BAD";[ $RC -eq 0 ]&&ok "$C CPU run $X READY"||bad "$C CPU run $X";[ $BOOTS -eq $((C-1)) ]&&ok "$C CPU run $X online"||bad "$C CPU run $X boots=$BOOTS";[ $BAD -eq 0 ]&&ok "$C CPU run $X clean"||bad "$C CPU run $X failures=$BAD";$G stop $N >/dev/null 2>&1||true;done;done
echo "RESULT: $P passed, $F failed";[ $F -eq 0 ]
