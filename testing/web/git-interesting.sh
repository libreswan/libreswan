#!/bin/sh

if test $# -lt 2; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <gitrev>

Is <gitrev> in <repodir> sufficiently "interesting" to test?

Interesting is loosely defined as changes in the code or testsuite;
but not changes in the testing or web infrastructure.

In addition, all merge points are considered interesting.

EOF
    exit 1
fi

set -eu

webdir=$(dirname $0)

repodir=$1 ; shift
gitrev=$1 ; shift

# All merges (commits with more than one parent) are "interesting".

parents=$(${webdir}/gime-git-parents.sh ${repodir} ${gitrev} | wc -l)
if test ${parents} -gt 1 ; then
    echo "${parents} parents"
    exit 0
fi

# All branches (commits with more than one child) are "interesting".

children=$(${webdir}/gime-git-children.sh ${repodir} ${gitrev} | wc -l)
if test ${children} -gt 1 ; then
    echo "${children} children"
    exit 0
fi

cd ${repodir}

# grep . exits non-zero when there is no input (i.e., the diff is
# empty); and this will cause the command to fail.

if git show "${gitrev}^{commit}" \
       Makefile \
       Makefile.inc \
       lib \
       mk \
       programs \
       include \
       testing/pluto \
       testing/sanitizers \
       testing/baseconfigs \
	| grep . > /dev/null ; then
    echo "interesting"
    exit 0
fi

exit 1
