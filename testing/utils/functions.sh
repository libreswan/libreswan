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
