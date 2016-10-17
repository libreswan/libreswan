#!/bin/sh

set -eu

if test "$#" -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <repodir> <resultsdir> ...

Use <repodir> to rebuild the <resultsdir> directories.

Because this script modifies the contents of <repodir> (for instance
to checkout the commit used to generate a test result), it needs a
dedicated repository.

The test output under <resultsdir> is left unchanged.

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)
repodir=$(cd $1 && pwd) ; shift
branch=$(${webdir}/gime-git-limb.sh ${repodir})

# Make certain that the repository has all the latest changes.
( cd ${repodir} && git checkout ${branch} )
origin=$(${webdir}/gime-git-origin.sh ${repodir} ${branch})
( cd ${repodir} && git fetch ${origin} )
( cd ${repodir} && git rebase ${origin} )

for d in "$@" ; do

    # Set things up
    if test ! -d "${d}" ; then
	echo "skipping ${d}: not a directory"
	continue
    fi
    destdir=$(cd ${d} && pwd)
    gitrev=$(${webdir}/gime-git-rev.sh $(basename ${destdir}))
    if test -z "${gitrev}" ; then
	echo "skipping ${d}: no git revision in directory name"
	continue
    fi

    # Checkout the commit used to create ${destdir}
    ( cd ${repodir} && git checkout ${branch} )
    ( cd ${repodir} && git checkout ${gitrev} )

    ${webdir}/build-results.sh ${repodir} ${destdir}
done

( cd ${repodir} && git checkout ${branch} )
