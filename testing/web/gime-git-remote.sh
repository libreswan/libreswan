#!/bin/sh

if test $# -ne 2; then
    cat >> /dev/stderr <<EOF
Usage:
    $0 <repodir> <branch>
Return the remote for <branch> in <repodir>.
EOF
    exit 1
fi

set -eu

bindir=$(dirname $0)

# switch to repodir
cd $1 ; shift

branch=$1 ; shift

git config --get branch.${branch}.remote
