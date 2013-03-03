#!/bin/bash
. ../../../kvmsetup.sh
. ./testparams.sh 
. ../setup.sh
. ../../utils/functions.sh

TCPDUMP_FILTER="not stp and not port 22"

TESTNAME=`basename $PWD`
echo "autodetect testname is $TESTNAME"

rm -fr OUTPUT/*
mkdir  -pm777 OUTPUT

# kill all hanging runkvm's, they get called swankvm
if [ -n "`pidof swankvm`" ] ; then
	echo "Killing existing swankvm VM controllers"
	killall swankvm
fi
# kill any lingering tcpdumps
if [ -n "`pidof tcpdump`" ] ; then
	echo "Killing existing tcpdump controllers"
	sudo killall tcpdump
fi

if [ ! -f eastrun.sh ] ; then
	RESPONDER=east
else
	P=`pwd`
	echo "can't identify RESPONDER no $P/eastinit.sh"
	exit 1
fi

NIC=""
NIC_PID=""
if [ -f nicinit.sh ] ; then
	echo "will start nic nicinit.sh"
	NIC=nic
fi


if [ -f westrun.sh ] ; then
	INITIATOR=west
	SWAN_PCAP=swan12.pcap
	TCPDUMP_DEV=swan12
elif [ -f roadrun.sh ] ; then
	INITIATOR=road
	SWAN_PCAP=swan12.pcap
	TCPDUMP_DEV=swan12
elif [ -f northrun.sh ] ; then
	INITIATOR=north
	SWAN_PCAP=swan13.pcap
	TCPDUMP_DEV=swan13
else 
	echo "can't identify INITIATOR"
	exit 1
fi

touch OUTPUT/pluto.$INITIATOR.log
touch OUTPUT/pluto.$RESPONDER.log 
chmod a+rw OUTPUT/pluto.$INITIATOR.log 
chmod a+rw OUTPUT/pluto.$RESPONDER.log


function wait_till_pid_end {
	NAME=$1 
	PID=$2
	echo "will wait till $NAME pid $PID ends"
	p=$PID
	set +e
	while [ "$p" == "$PID" ]
	do
		P1=`ps -p $PID | grep $PID`
		p=0
		if [ -n "$P1" ]
		then
			set $P1
			p=$1
		fi
		sleep 2
	done
	set -e
}

sudo /sbin/tcpdump -w ./OUTPUT/$SWAN_PCAP -n -i $TCPDUMP_DEV $TCPDUMP_FILTER &
TCPDUMP_PID=$! 
echo $TCPDUMP_PID  > ./OUTPUT/$SWAN_PCAP.pid

if [ -n "$NIC" ] ; then
	echo "../../utils/runkvm.py --host $NIC --testname $TESTNAME --reboot"
	../../utils/runkvm.py --host $NIC --testname $TESTNAME  &
	NIC_PID=$!
fi

echo "../../utils/runkvm.py --host $INITIATOR --testname $TESTNAME --reboot"
../../utils/runkvm.py --host $INITIATOR --testname $TESTNAME --reboot  &
INITIATOR_PID=$!  

echo "../../utils/runkvm.py --host $RESPONDER --testname $TESTNAME --reboot"
../../utils/runkvm.py --host $RESPONDER --testname $TESTNAME --reboot &
RESPONDER_PID=$!

wait_till_pid_end "$INITIATOR" $INITIATOR_PID
wait_till_pid_end "$RESPONDER" $RESPONDER_PID
echo "start final.sh on responder $RESPONDER for $TESTNAME"
../../utils/runkvm.py --final --hostname $RESPONDER --testname $TESTNAME &
RESPONDER_FINAL_PID=$!
wait_till_pid_end "$RESPONDER" $RESPONDER_FINAL_PID

# This causes this script to end itself?
#if [ -n "$NIC_PID" ] ; then
#	kill -9 $NIC_PID
#fi

TCPDUMP_PID_R=`pidof sudo`
if [ -f ./OUTPUT/$SWAN_PCAP.pid ] ; then
	TCPDUMP_PID=`cat  ./OUTPUT/$SWAN_PCAP.pid`
	for s in $TCPDUMP_PID_R
	do
		if [ $s -eq $TCPDUMP_PID ] ; then
			# -2 is SIGINT
			echo "kill $s"
                	sudo kill -2 $s
                fi
        done 
fi

initout=`consolediff ${INITIATOR} OUTPUT/${INITIATOR}.console.txt ${INITIATOR}.console.txt`
respout=`consolediff ${RESPONDER} OUTPUT/${RESPONDER}.console.txt ${RESPONDER}.console.txt`
echo "WARNING: tcpdump output is not yet compared to known good output!"
if [ "$initout" = "output matched" -a "$respout" = "output matched" ] ; then
	echo $TESTNAME PASSED
	echo "PASSED" > $PWD/RESULT
else
	echo $TESTNAME FAILED
	echo "FAILED" > $PWD/RESULT
	echo $initout
	echo $initout >> $PWD/RESULT
	echo $respout
	echo $respout >> $PWD/RESULT
fi

