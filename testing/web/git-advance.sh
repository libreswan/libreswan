#!/bin/sh

if test $# -lt 2; then
    cat <<EOF > /dev/stderr

Usage:

    $0 <repodir> <branch>

Advance <repodir> by one commit along <branch>.

EOF
    exit 1
fi

set -eu

webdir=$(dirname $0)
repodir=$1 ; shift
branch=$1 ; shift
origin=$(${webdir}/gime-git-origin.sh ${repodir} ${branch})

# Switch to the repo directory; this destroys the above relative paths
cd ${repodir}
repodir=
webdir=

# Where is the branch and where can it go.
branch_head=$(git rev-list --first-parent ${branch}^..${branch} | head -1)
next_head=$(git rev-list --first-parent HEAD..${branch} | tail -n 1)
next_origin=$(git rev-list --first-parent ${branch}..${origin}/${branch} | tail -n 1)

if test "${next_head}" = "${branch_head}"; then
    # Since the next checkout along the branch is the branch HEAD,
    # simply switch to the branch (HEAD).
    #
    # This forces the repo into branch tracking mode.
    git checkout ${branch}
elif test -n "${next_head}"; then
    # Advance HEAD checkout closer to the branch HEAD.
    git checkout ${next_head}
elif test -n "${next_origin}" ; then
    # Advance branch HEAD one checkout closer to ${origin}/${branch}.
    git rebase ${next_origin}
else
    exit 111
fi

git log HEAD ^HEAD^
