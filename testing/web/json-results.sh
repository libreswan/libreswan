#!/bin/sh

set -eu

if test "$#" -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <repodir> <resultsdir> ...

Use <repodir> to update the .json files under the <test-run-dir>
directories (where <test-run-dir> contains the results from a full
test run).

Because this script needs to modify the contents of <repodir> (for
instance to examine (checkout) the commit used to generate a test
run), it requires access to a dedicated repository.

The test output under <resultsdir> is left unchanged.

For convenience, if <test-run-dir> is a file (for instance,
<test-run-dir>/results.json) then the file is stripped off).

EOF
    exit 1
fi

bindir=$(cd $(dirname $0) && pwd)
utilsdir=$(cd ${bindir}/../utils && pwd)
makedir=$(cd ${bindir}/../.. && pwd)
repodir=$(cd $1 && pwd) ; shift
branch=$(${bindir}/gime-git-branch.sh ${repodir})
origin=$(cd ${repodir} && git config --get branch.${branch}.remote)

echo
echo Rebuilding: "$@"
echo

# Make certain that the repository has all the latest changes.
echo Updating repo ${repodir}
( cd ${repodir} && git checkout ${branch} )
( cd ${repodir} && git fetch ${origin} )
( cd ${repodir} && git rebase ${origin} )

for resultsdir in "$@" ; do

    echo ""
    echo "Rebuilding: ${resultsdir}"
    echo ""

    # for convenience, turn a file into the directory containing the
    # file
    if test -f ${resultsdir} ; then
	resultsdir=$(dirname ${resultsdir})
	# will be validated below
    fi

    # validate
    if test ! -d "${resultsdir}" ; then
	echo "skipping ${resultsdir}: not a directory"
	continue
    fi

    # determine the version
    gitrev=$(${bindir}/gime-git-rev.sh $(basename $(cd ${resultsdir} ; pwd)))
    if test -z "${gitrev}" ; then
	echo "skipping ${d}: no git revision in directory name"
	continue
    fi

    echo "Revert to revision ${gitrev}"
    ( cd ${repodir} && git reset --hard ${gitrev} )

    # the test list can be missing, and kvmresults works better when
    # it is present.
    if test ! -r ${resultsdir}/TESTLIST ; then
	cp ${repodir}/testing/pluto/TESTLIST ${resultsdir}
    fi

    echo "Rebuilding results and summary"
    (
	set -x
	${utilsdir}/kvmresults.py \
		   --exit-ok \
		   --test-kind '' \
		   --test-status '' \
		   --publish-results ${resultsdir} \
		   --testing-directory ${repodir}/testing \
		   ${resultsdir}
    )

    echo "Switching bach to HEAD"
    ( cd ${repodir} && git merge --quiet --ff-only )

done
