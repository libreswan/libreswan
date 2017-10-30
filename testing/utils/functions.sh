#!/bin/bash

#
#  Root out incorrect shell invocations by failing if invoked with the wrong shell.
#  This script uses extended BASH syntax, so it is NOT POSIX "/bin/sh" compliant.
if test -z "${BASH_VERSION}" ; then
	echo >&2 "Fatal-Error: testing/utils/functions.sh MUST be run under \"/bin/bash\"."
	exit 55
fi

#
#  DHR says, always eat your dogfood!:
# set -u -e
set -e

# ??? NOTE:
# This seems to only sometimes set $success.
# Whatever interesting settings are made seem to be lost by the caller :-(
consolediff() {
    prefix=$1
    output=$2
    ref=$3

    success=${success-true}
    fixedoutput=OUTPUT/${prefix}.console.txt
    rm -f $fixedoutput OUTPUT/${prefix}.console.diff

    ${LIBRESWANSRCDIR}/testing/utils/sanitizer.sh \
		      ${output} \
		      $PWD \
		      ${FIXUPDIR} ${FIXUPDIR2:-} \
		      > ${fixedoutput}

    if diff -w -N -u $ref $fixedoutput >OUTPUT/${prefix}.console.diff
    then
	echo "${prefix} Consoleoutput matched"
    else
	diffstat=`diff -w -N -u $ref $fixedoutput | diffstat -f 0`
	echo "${prefix} Consoleoutput differed '$diffstat'"

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
	if [ -f ./stop-tests-now ] ; then
		echo "****** skip test $testdir found stop-tests-now *****"
	else
		echo '***** KVM PLUTO RUNNING' $testdir${KLIPS_MODULE} '*******'
		if [ -d $testdir ] ; then
			cd $testdir
			${UTILS}/swantest
			cd ../
		else
			echo '**** Skipping non-existing test $testdir *****'
		fi
	fi
}

#
#  ???
skiptest() {
	testdir=$1
	testexpect=$2
	echo "****** skip test $testdir yet to be migrated to kvm style "
}

ctltest() {
	testdir=$1
        testexpect=$2
	echo "****** ctltest test $testdir yet to be migrated to kvm style "
}

umlXhost () {
	testdir=$1
        testexpect=$2
	echo "****** umlXhost test $testdir yet to be migrated to kvm style "
}

umlplutotest () {
	testdir=$1
	testexpect=$2
	echo "****** umlplutotest test $testdir yet to be migrated to kvm style "
}


###################################
#
#  test type: libtest
#
###################################

complibtest() {
    testobj=$1
    testsrc=$2

    CC=${CC-cc}

    ECHO=${ECHO-echo}

    symbol=`echo $testobj | tr 'a-z' 'A-Z'`_MAIN

    unset FILE
    SRCDIR=${SRCDIR-./}

    if [ -f ${SRCDIR}$testsrc ]
    then
	FILE=${SRCDIR}$testsrc
    elif [ -f ${LIBRESWANSRCDIR}/lib/libswan/$testsrc ]
    then
        FILE=${LIBRESWANSRCDIR}/lib/libswan/$testsrc
    elif [ -f ${LIBRESWANSRCDIR}/linux/net/klips/$testsrc ]
    then
        FILE=${LIBRESWANSRCDIR}/linux/net/klips/$testsrc
    elif [ -f ${LIBRESWANSRCDIR}/linux/lib/libswan/$testsrc ]
    then
        FILE=${LIBRESWANSRCDIR}/linux/lib/libswan/$testsrc
    elif [ -f ${LIBRESWANSRCDIR}/linux/net/ipsec/$testsrc ]
    then
        FILE=${LIBRESWANSRCDIR}/linux/net/ipsec/$testsrc
    fi

    eval $(cd ${LIBRESWANSRCDIR} && LIBRESWANSRCDIR=$(pwd) make --no-print-directory env )

    EXTRAFLAGS=
    EXTRALIBS=
    UNITTESTARGS=-r

    if [ -f ${SRCDIR}FLAGS ]; then
        ${ECHO} "   "Sourcing ${SRCDIR}FLAGS
	. ${SRCDIR}FLAGS
    fi

    if [ -f ${SRCDIR}FLAGS.$testobj ]
    then
        ${ECHO} "   "Sourcing ${SRCDIR}FLAGS.$testobj
	. ${SRCDIR}FLAGS.$testobj
    fi

    stat=99
    if [ -n "${FILE-}" -a -r "${FILE-}" ]
    then
	    ${ECHO} " ${CC} -g -o $testobj -DSWAN_TESTING -D$symbol ${MOREFLAGS} ${PORTINCLUDE} ${EXTRAFLAGS} -I${LIBRESWANSRCDIR}/linux/include -I${LIBRESWANSRCDIR} -I${LIBRESWANSRCDIR}/include ${FILE} ${LIBRESWANLIB} ${EXTRALIBS} -Iinclude/"
	    ${CC} -g -o $testobj -DSWAN_TESTING -D$symbol ${MOREFLAGS} ${PORTINCLUDE} ${EXTRAFLAGS} -I${LIBRESWANSRCDIR}/linux/include -I${LIBRESWANSRCDIR} -I${LIBRESWANSRCDIR}/include ${FILE} ${LIBRESWANLIB} ${EXTRALIBS} -Iinclude/
	    rm -rf lib-$testobj/OUTPUT
	    mkdir -p lib-$testobj/OUTPUT
    fi
}

# test entry point:
libtest() {
    testobj=$1
    testexpect=$2
    testsrc=$testobj.c

    ECHO=${ECHO-echo}

    ${ECHO} '**** make libtest COMPILING' $testsrc '****'
    complibtest $testobj $testsrc

    stat=99
    if [ -n "${FILE-}" -a -r "${FILE-}" ]
    then
	    export TEST_PURPOSE=regress

	    echo "file ../$testobj" >lib-$testobj/.gdbinit
	    echo "set args "${UNITTESTARGS} >>lib-$testobj/.gdbinit

	    ${ECHO} "   "Running $testobj
	    ( ulimit -c unlimited; cd lib-$testobj && eval ../$testobj ${UNITTESTARGS} >OUTPUT${KLIPS_MODULE}/$testobj.txt 2>&1 )


	    stat=$?
	    ${ECHO} "   "Exit code $stat
	    if [ $stat -gt 128 ]
	    then
		stat="$stat core"
	    else
		if [ -r OUTPUT.$testobj.txt ]
		then
		    if diff -w -N -u lib-$testobj/OUTPUT${KLIPS_MODULE}/$testobj.txt OUTPUT.$testobj.txt > lib-$testobj/OUTPUT${KLIPS_MODULE}/$testobj.output.diff
		    then
			${ECHO} "   ""output matched"
			stat="0"
		    else
			${ECHO} "   ""output differed"
			stat="1"
		    fi
		fi
            fi
    fi

    TEST_PURPOSE=regress  UML_BRAND=0 recordresults lib-$testobj "$testexpect" "$stat" lib-$testobj
}

# test entry point:
multilibtest() {
    testobj=$1
    testexpect=$2
    testsrc=$testobj.c

    ECHO=${ECHO-echo}

    ${ECHO} '**** make multilibtest COMPILING' $testsrc '****'
    complibtest $testobj $testsrc

    stat=99
    if [ -n "${FILE-}" -a -r "${FILE-}" ]
    then
	    export TEST_PURPOSE=regress

	    echo "file ../$testobj" >lib-$testobj/.gdbinit
	    echo "set args "${UNITTESTARGS} >>lib-$testobj/.gdbinit

	    ${ECHO} Multilib running lib-$testobj/testlist.sh for $testobj ${UNITTESTARGS}
	    ( ulimit -c unlimited; cd lib-$testobj && ./testlist.sh >OUTPUT${KLIPS_MODULE}/$testobj.txt 2>&1 )

	    stat=$?
	    ${ECHO} Exit code $stat
	    if [ $stat -gt 128 ]
	    then
		stat="$stat core"
	    else
		if [ -r OUTPUT.$testobj.txt ]
		then
		    if diff -w -N -u OUTPUT.$testobj.txt lib-$testobj/OUTPUT${KLIPS_MODULE}/$testobj.txt > lib-$testobj/OUTPUT${KLIPS_MODULE}/$testobj.output.diff
		    then
			${ECHO} "output matched"
			stat="0"
		    else
			echo "$testobj: output differed"
			stat="1"
		    fi
		fi
            fi
    fi

    TEST_PURPOSE=regress  UML_BRAND=0 recordresults lib-$testobj "$testexpect" "$stat" lib-$testobj false
}


#
#  ???
roguekill() {
    REPORT_NAME="$1"
    local rogue_sighted=""

    if [ -n "${REGRESSRESULTS-}" ]
    then
	rm -f $REGRESSRESULTS/$REPORT_NAME/roguelist.txt
	mkdir -p $REGRESSRESULTS/$REPORT_NAME
    fi

    # search for rogue UML
    local pointless=false
    local firstpass=true
    local other_rogues=""
    verboseecho "UML_BRAND=$UML_BRAND"
    for sig in KILL CONT KILL CONT KILL CONT KILL
    do
	if $pointless
	then
	    break;
	fi
	pointless=true
	# Debugging_note: the next line shows up as line 410 to -u, even if it's 417:
	for i in `grep -s -l '^'"${POOLSPACE}"'/[a-z]*/linux\>' /proc/[1-9]*/cmdline`
	do
	    local pdir=`dirname "$i"`
	    local badpid=`basename $pdir`
	    if [ ! -r $pdir/environ ] || strings $pdir/environ | grep "^UML_BRAND=$UML_BRAND"'$' >/dev/null
	    then
		echo "${sig}ING ROGUE UML: $badpid `tr '\000' ' ' <$pdir/cmdline`"
		if [ -n "${REGRESSRESULTS-}" ]
		then
		   echo "UML pid $pdir went ROGUE" >>$REGRESSRESULTS/$REPORT_NAME/roguelist.txt
		fi

		# the cwd is a good indication of what test was being executed.
		rogue_sighted=" rogue"
		pointless=false
		ls -l $pdir/cwd
		kill -$sig $badpid
	    elif $firstpass
	    then
		other_rogues="$other_rogues $badpid"
	    fi
	done
	# might take some realtime for a kill to work
	if ! $pointless
	then
	    sleep 2
	fi
	firstpass=false
    done
    if [ -n "$other_rogues" ]
    then
	echo "ROGUES without brand $UML_BRAND:"
	ps -f -w -p $other_rogues
    fi
    stat="${stat:-}${rogue_sighted}"; # I am guessing here as to the original intent --HD
}

#
# record results records the status of each test in
#   $REGRESSRESULTS/$REPORT_NAME/status
#
# If the status is negative, then the "OUTPUT${KLIPS_MODULE}" directory of the test is
# copied to $REGRESSRESULTS/$REPORT_NAME/OUTPUT${KLIPS_MODULE} as well.
#
# The file $testname/description.txt if it exists is copied as well.
#
# If $REGRESSRESULTS is not set, then nothing is done.
#
# See testing/utils/regress-summarizeresults.pl for a tool to build a nice
# report from these files.
#
# See testing/utils/regress-nightly.sh and regress-stage2.sh for code
# that sets up $REGRESSRESULTS.
#
# usage: recordresults testname testtype status REPORTNAME copybadresults
#
recordresults() {
    local testname="$1"
    local testexpect="$2"
    local status="$3"
    local REPORT_NAME="$4"
    local copybadresults="$5"

    if [ -z "$copybadresults" ]
    then
	copybadresults=true
    fi

    ECHO=${ECHO-echo}

    export REGRESSRESULTS
    roguekill $REPORT_NAME

    if [ -n "${REGRESSRESULTS-}" ]
    then
	rm -rf $REGRESSRESULTS/$REPORT_NAME
	mkdir -p $REGRESSRESULTS/$REPORT_NAME
	console=false
	packet=false

	# if there was a core file, add that to status
	cores=`( lookforcore $testname )`
	if [ ! -z "$cores" ]
	then
	    status="$status core"
	fi

	# if there was a rogue, add that to status
	if [ -f $REGRESSRESULTS/$REPORT_NAME/status/roguelist.txt ]
	then
	    status="$status rogue"
	fi

	# note that 0/1 is shell sense.
	case "$status" in
	    0) success=true;;
	    1) success=false; console=true;;
	    2) success=false; console=false; packet=true;;
	    99) success="missing 99"; console=false; packet=false;;
	    true)  success=true;;
	    false) success=false;;
	    succeed) success=true;;
	    fail)  success=false;;
	    yes)   success=true;;
	    no)    success=false;;
	    skipped) success=skipped;;
	    missing) success=missing;;
	    *)	success=false;;
	esac

	${ECHO} "Recording "'"'"$success: $status"'"'" to $REGRESSRESULTS/$REPORT_NAME/status"
	echo "$success: $status" >$REGRESSRESULTS/$REPORT_NAME/status
	echo console=$console >>$REGRESSRESULTS/$REPORT_NAME/status
	echo packet=$packet   >>$REGRESSRESULTS/$REPORT_NAME/status

	echo "$testexpect" >$REGRESSRESULTS/$REPORT_NAME/expected

	if [ -f $testname/description.txt ]
	then
	    cp $testname/description.txt $REGRESSRESULTS/$REPORT_NAME
	fi


	# the following is in a subprocess to protect against certain
	# testparams.sh which exit!
	(
	    if [ -r "$testdir/testparams.sh" ]
	    then
		. "$testdir/testparams.sh"
	    fi

	    case "${TEST_PURPOSE}" in
	    regress) echo ${TEST_PROB_REPORT} >$REGRESSRESULTS/$REPORT_NAME/regress.txt;;
	       goal) echo ${TEST_GOAL_ITEM}   >$REGRESSRESULTS/$REPORT_NAME/goal.txt;;
	    exploit) echo ${TEST_EXPLOIT_URL} >$REGRESSRESULTS/$REPORT_NAME/exploit.txt;;
		  *) echo "unknown TEST_PURPOSE ${TEST_PURPOSE}";;
	    esac
	)

	if $copybadresults
	then
	    case "$success" in
	    false)
		# this code is run only when success is false, so that we have
		# a record of why the test failed. If it succeeded, then the
		# possibly volumnous output is not interesting.
		#
		# NOTE: ${KLIPS_MODULE} is part of $REPORT_NAME
		rm -rf $REGRESSRESULTS/$REPORT_NAME/OUTPUT
		mkdir -p $REGRESSRESULTS/$REPORT_NAME/OUTPUT
		tar -C $testname/OUTPUT${KLIPS_MODULE} -c -f - . | (cd $REGRESSRESULTS/$REPORT_NAME/OUTPUT && tar xf - )
		;;
	    esac
	fi
    fi

    case "$status" in
    0)	echo '*******  PASSED '$REPORT_NAME' ********' ;;
    skipped)  echo '*******  SKIPPED '$REPORT_NAME' ********' ;;
    *)  echo '*******  FAILED '$REPORT_NAME' ********' ;;
    esac
}

#
#  ???
verboseecho() {
    if [ -n "${NETJIGVERBOSE-}" ]
    then
        echo $@
    fi
}

#
#  ???
lookforcore() {
    local testdir="$1"

    if [ -d "$testdir" ]
    then
	cd $testdir

	if [ -f ./testparams.sh ]
	then
	    . ./testparams.sh
	elif [ -f ../../default-testparams.sh ]
	then
		. ../../default-testparams.sh
	fi

	if [ -f ./add-testparams.sh ]
	then
	    . ./add-testparams.sh
	fi

	# get rid of any pluto core files.
	if [ -z "${XHOST_LIST-}" ]
	then
	    XHOST_LIST="EAST WEST JAPAN"
	fi

	export XHOST_LIST

	# Xhost script takes things from the environment.
	for host in $XHOST_LIST
	do
	    ROOT=$POOLSPACE/$host/root
	    if [ -f $ROOT/var/tmp/core ]
	    then
		mv $ROOT/var/tmp/core OUTPUT${KLIPS_MODULE}/pluto.$host.core
		echo "pluto.$host.core "
	    fi
	done
    fi
}

###################################
#
#  test type: unittest
#
# testparams.sh should specify a script to be run as $TESTSCRIPT
#          REF_CONSOLE_OUTPUT= name of reference output
#
# The script will be started with:
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#
#
# testparams.sh should set PROGRAMS= to a list of subdirs of programs/
#                that must be built before using the test. This allows
#                additional modules to be built.
#
# If there is a Makefile in the subdir, it will be invoked as
# "make checkprograms". It will have the above variables as well,
# and make get the build environment with
#    include ${ROOTDIR}/programs/Makefile.program
#
# The stdout of the script will be set to an output file, which will then
# be sanitized using the normal set of fixup scripts.
#
#
###################################

do_unittest() {

    export ROOTDIR=${OPENSWANSRCDIR}
    eval `(cd $ROOTDIR; make --no-print-directory env )`
    failnum=1

    if [ ! -x "$TESTSCRIPT" ]; then echo "TESTSCRIPT=$TESTSCRIPT is not executable"; exit 41; fi

    echo "BUILDING DEPENDENCIES"
    (cd ${ROOTDIR}/programs;
     for program in ${PROGRAMS}
     do
	if [ -d $program ]; then (cd $program && make programs checkprograms ); fi
     done)

    echo "BUILDING TEST CASE"
    # if there is a makefile, run it and bail if fails
    if [ -f Makefile ]; then
	if make checkprograms; then
	    :
	else
	    exit 1;
	fi
    fi

    # make sure we get all core dumps!
    ulimit -c unlimited
    export OBJDIRTOP

    OUTDIR=${OBJDIRTOP}/testing/${TESTSUBDIR}/${TESTNAME}
    mkdir -p ${OUTDIR}
    rm -f OUTPUT; ln -f -s ${OUTDIR} OUTPUT

    echo "RUNNING $TESTSCRIPT"
    ./$TESTSCRIPT >${OUTDIR}/console.txt
    echo "DONE    $TESTSCRIPT"

    stat=$?
    echo Exit code $stat
    if [ $stat -gt 128 ]
    then
	stat="$stat core"
    else
        consolediff "" OUTPUT/console.txt $REF_CONSOLE_OUTPUT
	case "$success" in
	true)	exit 0 ;;
	*)	exit $failnum ;;
	esac
    fi
}

#
#  ???
unittest() {
    testcase=$1
    testexpect=$2

    echo '**** make unittest RUNNING '$testcase' ****'

    echo Running $testobj
    ( preptest $testcase unittest false && do_unittest )
    stat=$?

    TEST_PURPOSE=regress recordresults $testcase "$testexpect" "$stat" $testcase false
}





