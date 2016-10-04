#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <gitrev>

Is <gitrev> in <repodir> sufficiently "interesting" to test?

Interesting is loosely defined as changes in the code or testsuite;
but not changes in the testing or web infrastructure.

EOF
    exit 1
fi

set -eu

repodir=$1 ; shift
gitrev=$1 ; shift

cd ${repodir}

# grep . exits non-zero when there is no input (i.e., the diff is
# empty); and this will cause this script to fail (set -e).

git show ${gitrev} \
    lib \
    mk \
    programs \
    include \
    testing/pluto \
    testing/sanitizers \
    testing/baseconfigs \
    | grep . > /dev/null
