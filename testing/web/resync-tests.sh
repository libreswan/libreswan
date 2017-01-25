#!/bin/sh

set -eu

if test "$#" -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <repodir> <resultsdir> ...

Use <repodir> to copy/update the test source files in <resultsdir>.

Do not run this from the current repo.  It needs to checkout the the
exact commit used to create <resultsdir>.

Any test output under <resultsdir> is left unchanged.

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)
repodir=$(cd $1 && pwd) ; shift

for d in "$@" ; do
    destdir=$(cd ${d} && pwd)
    gitrev=$(${webdir}/gime-git-rev.sh $(basename ${destdir}))
    ( cd ${repodir} && git checkout ${gitrev} )
    ${webdir}/rsync-tests.sh ${repodir} ${destdir}
done
