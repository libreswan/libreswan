#!/bin/sh

if test $# -lt 2 ; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir>

EOF
    exit 1
fi

webdir=$(dirname $0)

repodir=$1 ; shift
summarydir=$1 ; shift

for dir in ${summarydir}/*-g*-* ; do
    test -d ${dir} || continue
    hash=$(${webdir}/gime-git-rev.sh ${dir})
    rank=$(${webdir}/gime-git-rank.sh ${repodir} ${hash})
    echo ${rank} ${hash}
done | sort -r -n | tail -1 | awk '{print $2}'
