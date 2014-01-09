#!/bin/bash
. ../../../kvmsetup.sh
if [ -f ./testparams.sh ] ; then
	. ./testparams.sh 
else
	. ../../default-testparams.sh
fi
. ../setup.sh
. $LIBRESWANDIR/testing/utils/functions.sh 

if [ -f eastinit.sh ] ; then
        RESPONDER=east
else
        P=`pwd`
        echo "can't identify INITIATOR no $P/eastinit.sh"
        exit 1
fi

NIC=""
NIC_PID=""
if [ -f nicinit.sh ] ; then
        echo "will start nic nicinit.sh"
        NIC=nic
fi


if [ -f westinit.sh ] ; then
        INITIATOR=west
elif [ -f roadinit.sh ] ; then
        INITIATOR=road
elif [ -f northinit.sh ] ; then
        INITIATOR=north
else 
        echo "can't identify INITIATOR"
        exit 1
fi

consolediff ${INITIATOR} OUTPUT/${INITIATOR}.console.verbose.txt ${INITIATOR}.console.txt
consolediff ${RESPONDER} OUTPUT/${RESPONDER}.console.verbose.txt ${RESPONDER}.console.txt
