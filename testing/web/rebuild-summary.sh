#!/bin/sh

if test $# -lt 2 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir>

Rebuild <summarydir> from <summarydir>/*/results.json, using <repodir>
as a reference.

Because this script modifies <repodir> (for instance, downloading the
latest changes and updating the branch), it should be given a separate
dedicated repository.

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) ; pwd)
repodir=$(cd $1 ; pwd) ; shift
summarydir=$(cd $1 ; pwd) ; shift
branch=$(${webdir}/gime-git-limb.sh ${repodir})

# Make certain that the current branch of the repository has all the
# latest changes.
( cd ${repodir} && git checkout ${branch} )
origin=$(${webdir}/gime-git-origin.sh ${repodir} ${branch})
( cd ${repodir} && git fetch ${origin} )
( cd ${repodir} && git rebase ${origin} )

${webdir}/build-summary.sh ${repodir} ${summarydir} ${summarydir}/*/results.json
