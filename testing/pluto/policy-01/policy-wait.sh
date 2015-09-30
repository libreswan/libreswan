#!/bin/sh

lines=$1
count=20
until [ $count -eq 0 ] || [ `ipsec eroute | wc -l` -eq $lines ]
do
    count=`expr $count - 1`
    sleep 2
done >/dev/null



