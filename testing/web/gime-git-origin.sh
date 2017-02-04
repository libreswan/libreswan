#!/bin/sh

if test $# -lt 1; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> [ <branch> ]

Return the remote origin for <branch> in <repodir>.

EOF
    exit 1
fi

set -eu

webdir=$(dirname $0)
repodir=$1 ; shift
if test $# -gt 0; then
    branch=$1 ; shift
else
    branch=$(${webdir}/gime-git-branch.sh ${repodir})
fi

origin=$(cd ${repodir} ; git config --get branch.${branch}.remote)
echo ${origin}
