#!/bin/sh

if test $# -lt 2 ; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir> <gitrevs> ...

List, in cronological order, the hashes for git revisions in the
range:

   (<start>, <stop>]

See git rev-list's --reverse and --first-parent options.

EOF
    exit 1
fi

repodir=$1 ; shift

cd ${repodir}

git rev-list --abbrev-commit "$@"
