#!/bin/sh

set -u

if test $# -ne 2 ; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <summarydir> <rutdir>

Identify the git revision of the earliest test result (based on commit
rank) in <summarydir>.

If there are no test results, use <rutdir>'s HEAD.

EOF
    exit 1
fi

# paths need to be absolute as potentially cd'ing to $rutdir
bindir=$(cd $(dirname $0) && pwd)
summarydir=$(realpath $1) ; shift
rutdir=$1 ; shift

# Use the test results in ${summarydir} to create a list of hashes and
# then reduce that down to the earliest.
#
# Since the number of hashes can be large, use xargs.
#
# Since the number of hashes can be very large (i.e., xargs invokes
# its command multiple times), put the hashes through multiple
# invocations of merge-base.  Hopefully two is enough.

hashes=$(ls ${summarydir} \
	    | xargs --no-run-if-empty \
		    ${bindir}/gime-git-rev.sh \
	    | xargs --no-run-if-empty \
		    git -C ${rutdir} merge-base --octopus \
	    | xargs --no-run-if-empty \
		    git -C ${rutdir} merge-base --octopus \
      )

if test -n "${hashes}" ; then
    echo "${hashes}"
    exit 0
fi

hash=$(git -C ${rutdir} show --no-patch --format=%H HEAD)
echo "No results in ${summarydir} using HEAD ${hash}" 1>&2
echo ${hash}
exit 0
