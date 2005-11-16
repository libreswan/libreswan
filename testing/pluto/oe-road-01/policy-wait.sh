#!/bin/sh

count=20
until [ $count -eq 0 ] || (ipsec eroute | grep 0.0.0.0/0)
do 
    count=`expr $count - 1`
    sleep 2
done >/dev/null



