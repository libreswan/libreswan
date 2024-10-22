#!/bin/sh

if test $# -ne 1; then
    cat >>/dev/stderr <<EOF
Usage:
    $0 <repodir>
Use a heuristic to determine the branch name of the current detached
head.
EOF
    exit 1
fi

# switch to repodir
cd $1 ; shift

# Easy way, see what branch HEAD is on.

branch=$(git rev-parse --abbrev-ref HEAD)
if test ${branch} != HEAD ; then
    echo ${branch}
    exit 0
fi

# Hard way, follow checkouts until one hits a branch.

git reflog | awk '
BEGIN {
  found = ""
}
found == "" && $3 == "checkout:" && (sha == "" || sha == $1 ) {
  from = $(NF - 2)
  to = $NF
  # print "checkout:", "from=" from, "to=" to, "length(from)=" length(from) >> "/dev/stderr"
  if (length(from) != 40) {
    found = from
    # print "found=" found >> "/dev/stderr"
  } else {
    sha=substr(from, 1, 7)
    # print "sha=" sha >> "/dev/stderr"
  }
}
END {
  if (found) {
    print found
  } else {
    exit 1
  }
}
'
