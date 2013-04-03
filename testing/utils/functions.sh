#!/bin/bash

#
#  Root out incorrect shell invocations by failing if invoked with the wrong shell.
#  This script uses extended BASH syntax, so it is NOT POSIX "/bin/sh" compliant.
if test -z "${BASH_VERSION}" ; then 
	echo >&2 "Fatal-Error: testing/utils/functions.sh MUST be run under \"/bin/bash\"."
	exit 55
fi

#
#  DHR says, alwasy eat your dogfood!:
# set -u -e
set -e

# ??? NOTE:
# This seems to only sometimes set $success.
# Whatever interesting settings are made seem to be lost by the caller :-(
consolediff() {
    prefix=$1
    output=$2
    ref=$3

    cleanups="cat $output "
    success=${success-true}

    for fixup in `echo $REF_CONSOLE_FIXUPS`
    do
	if [ -f $FIXUPDIR/$fixup ]
	then
	    case $fixup in
		*.sed) cleanups="$cleanups | sed -f $FIXUPDIR/$fixup";;
		*.pl)  cleanups="$cleanups | perl $FIXUPDIR/$fixup";;
		*.awk) cleanups="$cleanups | awk -f $FIXUPDIR/$fixup";;
		    *) echo Unknown fixup type: $fixup;;
            esac
	elif [ -f $FIXUPDIR2/$fixup ]
	then
	    case $fixup in
		*.sed) cleanups="$cleanups | sed -f $FIXUPDIR2/$fixup";;
		*.pl)  cleanups="$cleanups | perl $FIXUPDIR2/$fixup";;
		*.awk) cleanups="$cleanups | awk -f $FIXUPDIR2/$fixup";;
		    *) echo Unknown fixup type: $fixup;;
            esac
	else
	    echo Fixup $fixup not found.
	    success="missing fixup"
	    return
        fi
    done

    fixedoutput=OUTPUT/${prefix}.console.txt
    rm -f $fixedoutput OUTPUT/${prefix}.console.diff
    $CONSOLEDIFFDEBUG && echo Cleanups is $cleanups
    eval $cleanups >$fixedoutput

    # stick terminating newline in for fun.
    echo >>$fixedoutput

    if diff -N -u -w -b -B $ref $fixedoutput >OUTPUT/${prefix}.console.diff
    then
	echo "${prefix}Console output matched"
    else
	echo "${prefix}Console output differed"

	case "$success" in
	true)	failnum=2 ;;
	esac

	success=false
    fi
}

# test entry point:
kvmplutotest () {
	testdir=$1
	testexpect=$2
	echo '***** KVM PLUTO RUNNING' $testdir${KLIPS_MODULE} '*******'
  	cd $testdir 
	${UTILS}/dotest.sh 
	cd ../
}

#
#  ???
skiptest() {
	testdir=$1
	testexpect=$2

	export TEST_PURPOSE=regress

	UML_BRAND=0 recordresults $testdir "$testexpect" skipped $testdir${KLIPS_MODULE} ""
}

ctltest() {
	testdir=$1
        testexpect=$2
	echo '****** ctltest test $testdir yet to be migrated to kvm style '
}

umlXhost () {
	testdir=$1
        testexpect=$2
	echo '****** umlXhost test $testdir yet to be migrated to kvm style '
}
