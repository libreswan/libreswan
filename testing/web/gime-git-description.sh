#!/bin/sh

if test $# -ne 1; then
    cat >> /dev/stderr <<EOF
Usage:
    $0 [ <repodir> ]
Use git describe et.al. to describe the current commit.
The format is:
    TAG-OFFSET-gREV-BRANCH
EOF
    exit 1
fi

set -eu

bindir=$(cd $(dirname $0) && pwd)

# cd to the repo
cd $1
shift

version=$(git describe --long)
branch=$(${bindir}/gime-git-branch.sh .)
echo ${version}-${branch}
