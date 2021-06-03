#!/bin/sh

# Reverse engineer 2016-08-08-0556-3.18-51-g00a7f80-dirty-branch
if test $# -lt 1 ; then
    cat <<EOF
Usage:
    $0 <result-directory> ...
Reverse engineer the git revision from a result directory.
EOF
    exit 1
fi

for d in "$@" ; do
    # reallink?
    realpath ${d} | sed -n -e 's/.*-g\([^-]*\)-[^/]*$/\1/p'
done
