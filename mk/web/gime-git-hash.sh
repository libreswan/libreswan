#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <hash> ...

Use git to make <hash> canonical.

EOF
    exit 1
fi

set -eu

bindir=$(cd $(dirname $0) && pwd)

 # switch to <repodir>
cd $1 ; shift

# so that when one fails things stumble on
for hash in "$@" ; do
    git show --no-patch --format=%H ${hash} -- || true
done
