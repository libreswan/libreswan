#!/bin/bash
. ../../../kvmsetup.sh
. ./testparams.sh 
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
else 
        echo "can't identify INITIATOR"
        exit 1
fi

consolediff ${INITIATOR} OUTPUT/${INITIATOR}.console.txt ${INITIATOR}.console.txt
consolediff ${RESPONDER} OUTPUT/${RESPONDER}.console.txt ${RESPONDER}.console.txt
