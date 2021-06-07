#!/bin/sh

set -u

if test $# -lt 1 ; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <summarydir> [ <repodir> ]

Identify the git revision of the earliest test result (based on commit
rank) in <summarydir>.

If there are no test results, use <repodir>'s HEAD.

EOF
    exit 1
fi

# paths need to be absolute as potentially cd'ing to $repodir
bindir=$(cd $(dirname $0) && pwd)
summarydir=$(cd $1 && pwd) ; shift
repodir=.
if test $# -gt 0 ; then
    cd $1
    shift
fi

# Create a list of the earliest hashes.  Use xargs to keep the length
# under control.
#
# Most likely this is just one hash, but as results get bigger you
# never know.

hashes=$(ls ${summarydir} \
	    | xargs --no-run-if-empty \
		    ${bindir}/gime-git-rev.sh \
	    | xargs --no-run-if-empty \
		    ${bindir}/gime-git-hash.sh ${repodir} \
	    | xargs --no-run-if-empty \
		    git merge-base --octopus )

if test -z "${hashes}" ; then
    hash=$(${bindir}/gime-git-hash.sh . HEAD)
    echo "No results in ${summarydir} using HEAD ${hash}" 1>&2
    echo ${hash}
    exit 0
fi

# Determine the first of them; git merge-base prints the raw hash.
#
# Assume that ${hashes} is not so long that more than two invocation
# of merge-base are needed (one above, one below).  If that turns out
# to be false then "fixing" merge-base to take stdin would be better.

git merge-base --octopus ${hashes}
