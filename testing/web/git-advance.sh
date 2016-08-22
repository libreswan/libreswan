#!/bin/sh

if test $# -ne 1; then
    cat <<EOF > /dev/stderr

Usage:

    $0 <branch>

Advance the current git tree by one commit (while tracking <branch>).

EOF
    exit 1
fi

set -eu

branch=$1 ; shift
origin=$(git config --get branch.${branch}.remote)
tip=$(git rev-list --first-parent ${branch}^..${branch} | head -1)

# Is this tree behind ${branch}?
next=$(git rev-list --first-parent HEAD..${branch} | tail -n 1)
if test "${next}" = "${tip}"; then
    # If next should be the branch tip, then checkout the branch
    # proper.
    git checkout ${branch}
    git log HEAD ^HEAD^
    exit 0
elif test -n "${next}"; then
    # Move closer to the branch tip.
    git checkout ${next}
    git log HEAD ^HEAD^
    exit 0
fi

# Is this tree behind ${origin}?
next=$(git rev-list --first-parent ${branch}..${origin}/${branch} | tail -n 1)
if test -n "${next}"; then
    git rebase ${next}
    git log HEAD ^HEAD^
    exit 0
fi

exit 111

