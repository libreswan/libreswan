#!/bin/sh

# Is the current commit sufficiently "interesting" to test?

# Interesting is loosely defined as changes in the code or testsuite;
# but not changes in the testing or web infrastructure.

set -eu

# grep . exits non-zero when there is no input; and this will cause
# this script to fail (set -e).

git diff HEAD ^HEAD^ \
    lib \
    programs \
    include \
    testing/pluto \
    testing/sanitizers \
    testing/baseconfigs \
    | grep . > /dev/null
