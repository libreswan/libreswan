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
start_hash=$(${webdir}/earliest-commit.sh ${repodir} ${summarydir})

${webdir}/json-commit.sh \
	 --json ${summarydir}/commits.json \
	 ${repodir} \
	 $(${webdir}/gime-git-revisions.sh ${repodir} ${start_hash}..${branch}) \
	 ${start_hash}

${webdir}/build-summary.sh ${repodir} ${summarydir}
