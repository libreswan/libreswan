#!/bin/sh

if test $# -lt 2 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir>

Rebuild <summarydir> from <summarydir>/*/, using <repodir> as a
reference.

This script does not modify <repodir>.

EOF
    exit 1
fi

repodir=$1 ; shift
summarydir=$1 ; shift

webdir=$(cd $(dirname $0) ; pwd)
branch=$(${webdir}/gime-git-limb.sh ${repodir})

for directory in ${summarydir}/*/ ; do
    test -r ${directory}/results.json || continue
    ${webdir}/json-summary.sh ${directory}/results.json > ${directory}/summary.json
done

${webdir}/build-summary.sh ${repodir} ${summarydir}
