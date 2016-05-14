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
        echo "can't identify RESPONDER no $P/eastinit.sh"
        exit 1
fi

consoles=`ls *.console.txt`
result=passed

for con in $consoles; do
	conv=`echo "$con" | sed -e "s/console/console.verbose/g"`
	host=`echo "$con" | sed -e "s/.console.txt//g"`
	if  [ ! -f $con ]; then
		echo "can't sanitize missing file $con"
		exit 1
	fi
	if [ ! -f OUTPUT/$conv ]; then
		echo "can't sanitize missing OUTPUT/$conv"
		exit 1
	fi
	#echo "sanize host $host OUTPUT/$conv $con"
	r=`consolediff "$host" "OUTPUT/$conv" "$con"`
	set $r
	m=$3
	if [ "$result" == "passed" ] && [ "$m" != "matched" ] ; then
                result="failed"
        fi
	echo "$r"
done;
echo "result $(basename $(pwd)) $result "
