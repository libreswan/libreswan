#!/bin/bash

set -eu

# Assuming that this script is in testing/utils, find the top-level
# directory.
LIBRESWANSRCDIR=$(dirname $(dirname $(dirname $(readlink -f $0))))

if [ ! -d OUTPUT ] ; then
	echo "$0: no OUTPUT subdirectory.  Is `pwd` a test directory?" >&2
	exit 1
fi

if [ -f ./testparams.sh ] ; then
	. ./testparams.sh
else
	. ${LIBRESWANSRCDIR}/testing/default-testparams.sh
fi

if [ -f ./add-testparams.sh ]
then
    . ./add-testparams.sh
fi

. ../setup.sh
. ${LIBRESWANSRCDIR}/testing/utils/functions.sh

if [ -f eastinit.sh ] ; then
        RESPONDER=east
else
        P=`pwd`
        echo "can't identify INITIATOR no $P/eastinit.sh"
        exit 1
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


ivc="./OUTPUT/${INITIATOR}.console.verbose.txt"
ic="./${INITIATOR}.console.txt"

rvc="./OUTPUT/${RESPONDER}.console.verbose.txt"
rc="./${RESPONDER}.console.txt"

result="passed"
for f in $ivc $ic $rvc $rc ; do
	if [ ! -f $ivc ] ; then
		echo "missing required file $f"
		result="passed"
	fi
done

if [ "$result" == "passed" ] ; then
	cdiff1=`consolediff ${INITIATOR} ${ivc} ${ic}`
	set  $cdiff1
	m=$3
	if [ "$m" != "matched" ] ; then
		result="failed"
	fi
	cdiff2=`consolediff ${RESPONDER} ${rvc} ${rc}`
	set  $cdiff2
	m=$3
	if [ "$m" != "matched" ] ; then
		result="failed"
	fi
fi

echo $cdiff1
echo $cdiff2
echo "result $(basename $(pwd)) $result "
