#!/bin/sh

if test $# -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

    $0 <repodir> <destdir>

Use <repodir> to determine the previous test result to <destdir>.

EOF
    exit 1
fi

set -eu

webdir=$(cd $(dirname $0) && pwd)
repodir=$(cd $1 && pwd ) ; shift
destdir=$(cd $1 && pwd) ; shift
destrev=$(${webdir}/gime-git-rev.sh ${destdir})

cd ${destdir}/..

ls | \
    while read dir ; do
	test -d "${dir}" || continue
	rev=$(${webdir}/gime-git-rev.sh ${dir})
	test -n "${rev}" || continue
	rank=$(${webdir}/gime-git-rank.sh ${repodir} ${rev})
	echo ${rank} ${rev} ${PWD}/${dir}
    done | \
    sort -n | \
    awk "/ ${destrev} / { if (prev) print prev } ; { prev=\$3 }"
