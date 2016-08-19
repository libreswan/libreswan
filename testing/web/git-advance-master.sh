#!/bin/sh

set -eu

git checkout master
next=$(git rev-list --first-parent master..origin/master | tail -n 1)
test -n "${next}" || exit 111
git rebase ${next}

cat <<EOF

Pending commits:

EOF
git log origin/master ^HEAD

cat <<EOF

New commit:

EOF
git log HEAD ^HEAD^
