#!/bin/sh

if test $# -lt 2 ; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir>

Identify the git revision of the earliest test result (based on commit
rank) in <summarydir>.

EOF
    exit 1
fi

webdir=$(dirname $0)

repodir=$1 ; shift
summarydir=$1 ; shift

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
    echo "No results in ${summarydir}" 1>&2
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
