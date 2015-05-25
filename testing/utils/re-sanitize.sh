#!/bin/bash

# re-sanitize.sh: re-run the console log sanitizer scripts for one test
#
# The current directory should be a specific test's directory.
# Synopsis: cd TEST ; ../../utils/re-sanitize.sh
#
# Each OUTPUT/${host}.console.verbose.txt will be used to create a new
# OUTPUT/${host}.console.txt and OUTPUT/${host}.console.diff
# If the resulting OUTPUT/${host}.console.diff is empty, it is removed.

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

. ../setup.sh
. ${LIBRESWANSRCDIR}/testing/utils/functions.sh

failure=0

for host in $(../../utils/kvmhosts.sh); do
    # The host list includes "nic" but that is ok as the checks below
    # filter it out.
    if [ -f "${host}.console.txt" ]; then
	#echo "re-sanitizing ${host}"
	# sanitize last run
	if [ -f OUTPUT/${host}.console.verbose.txt ]; then
	    cleanups="cat OUTPUT/${host}.console.verbose.txt "
	    for fixup in `echo $REF_CONSOLE_FIXUPS`; do

		if [ -f $FIXUPDIR/$fixup ]; then
		    case $fixup in
			*.sed) cleanups="$cleanups | sed -f $FIXUPDIR/$fixup";;
			*.pl)  cleanups="$cleanups | perl $FIXUPDIR/$fixup";;
			*.awk) cleanups="$cleanups | awk -f $FIXUPDIR/$fixup";;
			*) echo Unknown fixup type: $fixup;;
		    esac
		elif [ -f $FIXUPDIR2/$fixup ]; then
		    case $fixup in
			*.sed) cleanups="$cleanups | sed -f $FIXUPDIR2/$fixup";;
			*.pl)  cleanups="$cleanups | perl $FIXUPDIR2/$fixup";;
			*.awk) cleanups="$cleanups | awk -f $FIXUPDIR2/$fixup";;
			*) echo Unknown fixup type: $fixup;;
		    esac
		else
		    echo Fixup $fixup not found.
		    return
		fi
	    done

	    fixedoutput=OUTPUT/${host}.console.txt
	    rm -f $fixedoutput OUTPUT/${host}.console.diff
	    ## debug echo $cleanups
	    eval $cleanups >$fixedoutput
	    # stick terminating newline in for fun.
	    echo >>$fixedoutput
	    if diff -N -u -w -b -B ${host}.console.txt $fixedoutput >OUTPUT/${host}.console.diff; then
		echo "# ${host}Console output matched"
	    else
		echo "# ${host}Console output differed"
		failure=1
	    fi
	    if [ -f OUTPUT/${host}.console.diff -a \! -s OUTPUT/${host}.console.diff ]; then
		rm OUTPUT/${host}.console.diff
	    fi
	fi
    fi
done

if [ $failure -eq 0 ]; then
    echo "$(basename $(pwd)): passed"
else
    echo "$(basename $(pwd)): FAILED"
fi
