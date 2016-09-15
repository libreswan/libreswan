#!/bin/sh

if test $# -lt 1; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir>

Use a heuristic to determine the branch name of the current detached
head.

EOF
    exit 1
fi

repodir=$(cd $1 && pwd) ; shift

cd ${repodir}

git reflog | awk '
BEGIN {
  found = ""
}
found == "" && $3 == "checkout:" && (sha == "" || sha == $1 ) {
  from = $(NF - 2)
  to = $NF
  print from, to, length(from) >> "/dev/stderr"
  if (length(from) != 40) {
    found = from
  } else {
    sha=substr(from, 1, 7)
    print sha >> "/dev/stderr"
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
