#!/bin/sh

set -eu

if test $# -ne 1 ; then
    cat <<EOF >/dev/stderr

Usage:

    $0 <results-directory>

Find tests under broken that consistently fail.

EOF

    exit 1
fi

cd $1

# ./run/TESTLIST
runs=$(find . -name TESTLIST -print -prune | cut -d/ -f2 | sort -n -r)

# Need to ignore first directory as that is "in-progress"; should just
# trab directories[1]
TESTLIST=$(set - ${runs} ; echo $1)/TESTLIST
if test -z "${TESTLIST}" ; then
    echo $TESTLIST not found 1>&2
    exit 1
fi
echo ${TESTLIST} 1>&2

while read kind test expectation junk ; do
    case "${kind}" in
	kvmplutotest ) ;;
	* ) continue ;;
    esac
    case "${expectation}" in
	good ) ;;
	* ) continue ;;
    esac
    passed=
    for run in ${runs} ; do
	result=${run}/${test}/OUTPUT/RESULT
	if test ! -r ${result} ; then
	    # mising is treated like a fail; probably when the test
	    # was added.
	    continue
	fi
	if grep -e '"result" *: *"passed"' < ${result} > /dev/null ; then
	    passed=${run}
	    break
	fi
    done
    if test -z "${passed}" ; then
	echo ${test}
    fi
done < ${TESTLIST}
