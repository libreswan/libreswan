#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <branch>

Return the remote for <branch> in <repodir>.

EOF
    exit 1
fi

set -eu

webdir=$(dirname $0)
repodir=$1 ; shift
branch=$1 ; shift

cd ${repodir}
git config --get branch.${branch}.remote
