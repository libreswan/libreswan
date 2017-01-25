#!/bin/sh

if test $# -lt 2 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <gitrev>

List the parents of <gitrev>, one per line, first-parent first.

EOF
    exit 1
fi

repodir=$1 ; shift
gitrev=$1 ; shift

cd ${repodir}

for hash in $(git show --no-patch --format=%p ${gitrev}) ; do
    echo ${hash}
done
