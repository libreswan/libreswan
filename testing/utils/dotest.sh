#!/bin/bash
. ./testparams.sh 

rm -fr OUTPUT/*
mkdir  -m777 OUTPUT


if [ -f eastinit.sh ] ; then
	RESPONDER=east
fi

if [ -f westinit.sh ] ; then
	INITIATOR=west
elif [ -f roadinit.sh ] ; then
	INITIATOR=road
else 
	echo "can't idenity INITIATOR"
	exit 1
fi

touch OUTPUT/pluto.$INITIATOR.log
touch OUTPUT/pluto.$RESPONDER.log 
chmod a+rw OUTPUT/pluto.$INITIATOR.log 
chmod a+rw OUTPUT/pluto.$RESPONDER.log

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

../../utils/runkvm.py --host $INITIATOR --testname $TESTNAME  &
INITIATOR_PID=$!  
../../utils/runkvm.py --host $RESPONDER --testname $TESTNAME  &
RESPONDER_PID=$!

wait_till_pid_end "$INITIATOR" $INITIATOR_PID
wait_till_pid_end "$RESPONDER" $RESPONDER_PID

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
