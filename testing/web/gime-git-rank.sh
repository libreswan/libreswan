#!/bin/sh

if test $# -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir> <gitrev>

Print the 'rank' of commit <gitrev> in <repodir>, where 'rank'
provides a simplistic way to order commits (since commit date is
proving unreliable).

The bigger the number, the newer the commit.

EOF
    exit 1
fi

set -eu

repodir=$1 ; shift
rev=$1 ; shift

cd ${repodir}
git rev-list --count ${rev}
