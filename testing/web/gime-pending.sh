#!/bin/sh

if test $# -lt 3 ; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <summarydir> <repodir> <revlist> ...

Go through <rev-list> printing any commits that do not have results in
<summarydir> in <new>-<old> order.

EOF
    exit 1
fi

summarydir=$1 ; shift
repodir=$1 ; shift

webdir=$(dirname $0)

for revlist in "$@" ; do
    ${webdir}/gime-git-revisions.sh ${repodir} ${revlist} | \
	while read hash ; do \
	    if test -d ${summarydir}/*-g${hash}-* ; then
		continue
	    fi
	    if ${webdir}/git-interesting.sh ${repodir} ${hash} ; then
		echo ${hash}
	    fi
	done
done
