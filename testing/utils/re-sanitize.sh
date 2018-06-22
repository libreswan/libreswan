#!/bin/bash

# re-sanitize.sh: re-run the console log sanitizer scripts for one test
#
# The current directory should be a specific test's directory.
# Synopsis: cd TEST ; ../../utils/re-sanitize.sh
#
# The files:
#
#    OUTPUT/${host}.console.verbose.txt
#    OUTPUT/${host}.pluto.log
#
# will be used to create a new OUTPUT/${host}.console.txt and
# OUTPUT/${host}.console.diff
#
# If every ${host}.console.txt file has a corresponding, and empty,
# OUTPUT/${host}.console.diff file, then the test finished and passed.
#
# Note: while leaving empty console.diff files around is somewhat
# annoying it is backward compatible and makes verifying completion
# easier.

set -ue

# Assuming that this script is in testing/utils, find the top-level
# directory.
LIBRESWANSRCDIR=$(dirname $(dirname $(dirname $(readlink -f $0))))

if [ ! -d OUTPUT ]; then
    echo "$0: no OUTPUT subdirectory.  Is `pwd` a test directory?" >&2
    exit 1
fi

if [ -f ./testparams.sh ]; then
    . ./testparams.sh
else
    . ${LIBRESWANSRCDIR}/testing/default-testparams.sh
fi

. $LIBRESWANSRCDIR/testing/pluto/setup.sh

failure=0

check_console_log_for()
{
    if grep "$1" OUTPUT/${host}.console.txt >> OUTPUT/${host}.console.tmp; then
	echo "# ${host} $1"
	failure=1
    fi
}

check_pluto_log_for()
{
    if test -r OUTPUT/${host}.pluto.log; then
	if grep "$1" OUTPUT/${host}.pluto.log >> OUTPUT/${host}.console.tmp; then
	    echo "# ${host} $1"
	    failure=1
	fi
    fi
}

for host in $(${LIBRESWANSRCDIR}/testing/utils/kvmhosts.sh); do
    # The host list includes "nic" but that is ok as the checks below
    # filter it out.
    if [ -f "${host}.console.txt" ]; then
	#echo "re-sanitizing ${host}"
	rm -f OUTPUT/${host}.console.tmp
	touch OUTPUT/${host}.console.tmp
	# sanitize last run
	if [ ! -f OUTPUT/${host}.console.verbose.txt ]; then
	    echo "# ${host}.console.verbose.txt missing"
	    echo "${host}.console.verbose.txt" >> OUTPUT/${host}.console.tmp
	    failure=1
	else
	    fixedoutput=OUTPUT/${host}.console.txt
	    ${LIBRESWANSRCDIR}/testing/utils/sanitizer.sh \
			      OUTPUT/${host}.console.verbose.txt \
			      $PWD \
			      ${FIXUPDIR} ${FIXUPDIR2:-} \
			      > ${fixedoutput}

	    if diff -w -N -u ${host}.console.txt $fixedoutput >OUTPUT/${host}.console.tmp; then
		echo "# ${host} Console output matched"
	    else
		echo "# ${host} Console output differed"
		failure=1
	    fi
	    check_console_log_for '^CORE FOUND'
	    check_console_log_for SEGFAULT
	    check_console_log_for GPFAULT
	    check_pluto_log_for 'ASSERTION FAILED'
	    check_pluto_log_for 'EXPECTATION FAILED'
	    # this blats CORE into all the .diff files; better than nothing
	    for i in OUTPUT/core* ; do
		if [ -f "$i" ] ; then
		    echo "# CORE: $i"
		    echo "$i " >> OUTPUT/${host}.console.tmp
		fi
	    done
	fi
	mv OUTPUT/${host}.console.tmp OUTPUT/${host}.console.diff
    fi
done

if [ $failure -eq 0 ]; then
    echo "$(basename $(pwd)): passed"
    exit 0
else
    echo "$(basename $(pwd)): FAILED"
    exit 1
fi
