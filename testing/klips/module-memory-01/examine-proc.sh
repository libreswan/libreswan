#!/bin/sh
TZ=GMT export TZ

# /tmp/proc_meminfo-no-ipsec-mod-01 is saved before the module is
# loaded, in ../../utils/netjig.tcl

cat /proc/meminfo >/tmp/proc_meminfo-ipsec-mod-01

PASS=1
#while [ $PASS -le $MOD_LOAD_ITERATIONS ];
while [ $PASS -le 5 ]; do PASS_STR=`printf "%02d" $PASS`; rmmod ipsec; cat /proc/meminfo >/tmp/proc_meminfo-no-ipsec-mod-$PASS_STR; insmod /ipsec.o; cat /proc/meminfo >/tmp/proc_meminfo-ipsec-mod-$PASS_STR; let PASS=$PASS+1; done

for file in /tmp/proc_*; do   echo PROC-$file;   cat $file; done
echo PROC_DONE


