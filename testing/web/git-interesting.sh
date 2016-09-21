#!/bin/sh

if test $# -lt 1; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir>

Is the HEAD of <repodir> sufficiently "interesting" to test?

Interesting is loosely defined as changes in the code or testsuite;
but not changes in the testing or web infrastructure.

EOF
    exit 1
fi

set -eu

repodir=$1 ; shift

cd ${repodir}

# grep . exits non-zero when there is no input; and this will cause
# this script to fail (set -e).

git diff HEAD ^HEAD^ \
    lib \
    mk \
    programs \
    include \
    testing/pluto \
    testing/sanitizers \
    testing/baseconfigs \
    | grep . > /dev/null
