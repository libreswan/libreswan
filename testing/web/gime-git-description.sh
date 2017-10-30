#!/bin/sh

if test $# -gt 1; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ <repodir> ]

Use git describe et.al. to describe the current commit.  The format
is:

    TAG-OFFSET-gREV-BRANCH

EOF
    exit 1
fi

set -eu

webdir=$(cd $(dirname $0) && pwd)

# cd to the repo
if test $# -gt 0 ; then
    cd $1
    shift
fi

version=$(git describe --long)
branch=$(${webdir}/gime-git-branch.sh .)
echo ${version}-${branch}
