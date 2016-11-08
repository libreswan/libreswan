#!/bin/sh

if test $# -ne 3; then
  cat >> /dev/stderr <<EOF

Usage:

    $0 <summarydir> <repodir> <first-hash>

Print something to do.

EOF
  exit 1
fi

summarydir=$1 ; shift
repodir=$1 ; shift
start_hash=$1 ; shift

webdir=$(dirname $0)

# Get smarter later
${webdir}/gime-pending.sh ${summarydir} ${repodir} ${start_hash}..HEAD | head -1
