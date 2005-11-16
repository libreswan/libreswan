#!/bin/sh

count=20
until (ipsec eroute | grep "%trap" > /dev/null)
do
	count=`expr $count - 1`
	if [ $count -eq 0 ]
	then
		echo FAILED to find packetdefault implicit conn
		ipsec eroute
		exit 1
	fi
	sleep 1
done




