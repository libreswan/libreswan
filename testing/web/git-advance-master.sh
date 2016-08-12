#!/bin/sh

set -eux

git checkout master
git fetch origin
next=$(git rev-list --first-parent master..origin/master | tail -n 1)
test -n "${next}" || exit 0
git rebase ${next}
