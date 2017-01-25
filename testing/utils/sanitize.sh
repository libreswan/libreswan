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

. ${LIBRESWANSRCDIR}/testing/pluto/setup.sh
. ${LIBRESWANSRCDIR}/testing/utils/functions.sh

if [ -f eastinit.sh ] ; then
        RESPONDER=east
else
        P=`pwd`
        echo "can't identify RESPONDER no $P/eastinit.sh"
        exit 1
fi
set +e
consoles=`ls *.console.txt 2>/dev/null || echo "NOFILES"`
set -e

# this blats CORE into all the .diff files; better than nothing
for i in OUTPUT/core* ; do
	if [ -f "$i" ] ; then
		echo "# CORE: $i"
	fi
done

result=notset
if [ "$consoles" != "NOFILES" ]; then
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

		#echo "sanitize host $host OUTPUT/$conv $con"
		r=`consolediff "$host" "OUTPUT/$conv" "$con"`
		set $r
		m=$3

		if [ "$result" == "notset" ] && [ "$m" == "matched" ]; then
			result="passed"
		fi
		if [ "$m" != "matched" ] ; then
			result="failed"
		fi
		echo "$r"
	done;
else
	result=failed
	vconsoles=`ls OUTPUT/*.console.verbose.txt`
	for conv in $vconsoles; do
		con1=`echo "$conv" | sed -e "s/console.verbose/console/g"`
		con=`echo "$con1" | sed -e "s/OUTPUT\///g"`
		host=`echo "$con" | sed -e "s/.console.txt//g"`

		if [ ! -f $conv ]; then
			echo "can't sanitize missing file $conv"
			exit 1
		fi
		r=`consolediff "$host" "$conv" "$con"`
		echo "$host Consoleoutput new"

done;
fi

echo "result $(basename $(pwd)) $result "
