#!/bin/sh

if test $# -lt 1; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir>

Return <repodirs> current tracking branch.

EOF
    exit 1
fi

set -eu

repodir=$1 ; shift
branch=$(cd ${repodir} ; git rev-parse --abbrev-ref HEAD)

# Barf if this isn't tracking a branch
if test "${branch}" = HEAD ; then
    cat >> /dev/stderr <<EOF
${repodir} does not seem to be tracking a branch.
EOF
    exit 1
fi

echo ${branch}
