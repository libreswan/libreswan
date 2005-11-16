#!/bin/sh

thing=$1
count=20

until (ipsec eroute | grep "$thing" > /dev/null)
do
	count=`expr $count - 1`
	if [ $count -eq 0 ]
	then
		echo FAILED to find $thing
		ipsec eroute
		exit 1
	fi
	sleep 1
done


