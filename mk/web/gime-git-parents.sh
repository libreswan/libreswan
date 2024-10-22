#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF
Usage:
    $0 <repodir> <hash>
Use git to make <hash> canonical.
EOF
    exit 1
fi

set -eu

bindir=$(cd $(dirname $0) && pwd)

# cd to the repo
cd $1
shift

# so that if one hash is invalid things stumble along
for hash in "$@" ; do
    git show --no-patch --format=%P "${hash}^{commit}" --
done
