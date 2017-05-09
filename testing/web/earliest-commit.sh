#!/bin/sh

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
webdir=$(cd $(dirname $0) && pwd)
summarydir=$(cd $1 && pwd) ; shift

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
		    ${webdir}/gime-git-rev.sh \
	    | xargs --no-run-if-empty \
		    git show --ignore-missing --no-patch --format=%h \
	    | xargs --no-run-if-empty \
		    git merge-base --octopus )
if test -z "${hashes}" ; then
    hash=$(git show --no-patch --format=%h HEAD)
    echo "No results in ${summarydir} using HEAD ${hash}" 1>&2
    echo $hash
    exit 0
fi

# determine the first of them; need to pretty print the result (git
# merge-base doesn't handle --format).
#
# Assume that ${hashes} isn't so long that more than two iterations of
# merge-base are needed.  If that turns out to be false then "fixing"
# merge-base to take stdin would be better.

git show --no-patch --format=%h \
    $(git merge-base --octopus ${hashes})
