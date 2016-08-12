#!/bin/sh

set -eu

if test "$#" -lt 3; then
    cat <<EOF > /dev/stderr

Usage:

   $0 <repo> <results-directory> ...

Using <repo>, update the testsuite files in <results-directory>.  The
test results in <results-directory> are left unchanged.

Do not run this from the current repo (it needs to checkout the the
exact commit used to create <results-directory>).

EOF
    exit 1
fi

what=$1 ; shift
repo=$(cd $1 && pwd) ; shift

cwd=$(pwd)
webdir=$(cd $(dirname $0) && pwd)

for d in "$@" ; do
    destdir=$(cd ${d} && pwd)
    gitrev=$(${webdir}/gime-git-rev.sh $(basename ${d}))
    ${webdir}/rsync-tests.sh ${repo} ${destdir} ${gitrev}
done
