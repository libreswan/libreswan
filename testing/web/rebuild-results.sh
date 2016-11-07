#!/bin/sh

set -eu

if test "$#" -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <repodir> <resultsdir>|results.json ...

Use <repodir> to rebuild the <resultsdir> directories.

Because this script modifies the contents of <repodir> (for instance
to examine (checkout) the commit used to generate a test result), it
needs access to a dedicated repository.

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

for destdir in "$@" ; do

    echo ""
    echo "${destdir}"
    echo ""

    if test $(basename ${destdir}) = results.json ; then
	# let check below confirm this is valid
	destdir=$(dirname ${destdir})
    fi
    if test ! -d "${destdir}" ; then
	echo "skipping ${destdir}: not a directory"
	continue
    fi

    # Set things up
    gitrev=$(${webdir}/gime-git-rev.sh $(basename ${destdir}))
    if test -z "${gitrev}" ; then
	echo "skipping ${d}: no git revision in directory name"
	continue
    fi

    echo "Save (compress) any uncompressed log files"
    find ${destdir} -type f -name '*.log' -print \
	| xargs --no-run-if-empty bzip2 --compress --force -9 -v

    echo "Extract (uncompress) scratch log files"
    find ${destdir} -type f -name '*.log.bz2' -print \
	| xargs --no-run-if-empty bzip2 --decompress --keep

    echo "Revert to revision ${gitrev}"
    ( cd ${repodir} && git reset --hard ${gitrev} )

    echo "Rebuilding results"
    ${webdir}/build-results.sh ${repodir} ${destdir}

    echo "Switching bach to HEAD"
    ( cd ${repodir} && git merge --quiet --ff-only )

    echo "Removing scratch log files"
    find ${destdir} -type f -name '*.log' -print \
	 | xargs --no-run-if-empty rm

done

( cd ${repodir} && git checkout ${branch} )
