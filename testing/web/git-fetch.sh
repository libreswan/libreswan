#!/bin/sh

if test $# -lt 1; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir>

Fetch <repodir>'s remote origin as determined by the current branch.

EOF
    exit 1
fi

set -eu

webdir=$(dirname $0)
repodir=$1 ; shift
branch=$(${webdir}/gime-git-branch.sh ${repodir})
origin=$(${webdir}/gime-git-origin.sh ${repodir} ${branch})

cd ${repodir}
repodir=
webdir=

git fetch ${origin}
