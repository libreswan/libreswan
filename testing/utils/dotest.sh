#!/bin/bash

. ../../../umlsetup.sh
. ../setup.sh
. ./testparams.sh

rm -fr OUTPUT/*
mkdir  -m777 OUTPUT
touch OUTPUT/pluto.east.log
touch OUTPUT/pluto.west.log 
chmod a+rw OUTPUT/pluto.east.log 
chmod a+rw OUTPUT/pluto.west.log 

SWAN12_PCAP=swan12.pcap

function wait_till_pid_end {
	NAME=$1 
	PID=$2
	echo "will wait till $NAME pid $PID ends"
	p=$PID
	while [ "$p" == "$PID" ]
	do
		P1=`ps -p $PID | grep $PID`
		p=0
		if [ -n "$P1" ]
		then
			set $P1
			p=$1
		fi
	done
}

sudo /sbin/tcpdump -w ./OUTPUT/$SWAN12_PCAP -n -i swan12  not port 22 & 
TCPDUMP_PID=$! 
echo $TCPDUMP_PID  > ./OUTPUT/$SWAN12_PCAP.pid

../../utils/runkvm.py --host east --test $TESTNAME  &
EAST_PID=$!  
../../utils/runkvm.py --host west --test $TESTNAME  &
WEST_PID=$!

wait_till_pid_end "runvm.py-west" $WEST_PID 
wait_till_pid_end "runvm.py-east" $EAST_PID 

TCPDUMP_PID_R=`pidof sudo`
if [ -f ./OUTPUT/$SWAN12_PCAP.pid ] ; then
	TCPDUMP_PID=`cat  ./OUTPUT/$SWAN12_PCAP.pid`
	for s in $TCPDUMP_PID_R
	do
		if [ $s -eq $TCPDUMP_PID ] ; then
			# -2 is SIGINT
			echo "kill $s"
                	sudo kill -2 $s
			sleep 1
                	sudo kill -9 $s
                fi
        done 
fi
