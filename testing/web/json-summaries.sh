#!/bin/sh

set -eu

if test "$#" -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <repodir> [- | <summary.json> ...]

Using <repodir> (to map the abbreviated hash in the result directory
name onto a full hash) merge the <summary.json> files into a single
summaries.json on STDOUT.

'-' indicates the list of summary.json files is on stdin.

The test output is left unchanged.

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)

repodir=$(cd $1 && pwd) ; shift

if test $# -eq 1 -a x"$1" = x"-" ; then
    cat
else
    for d in "$@"; do
	echo "$d"
    done
fi | while read d; do
    dir=$(dirname $d)
    hash=$(${webdir}/gime-git-rev.sh $dir)
    hash=$(cd $repodir && git show --no-patch --format=%H ${hash})
    if test "${hash}" = "" ; then
	hash=null
    fi
    # let any existing hash override above
    jq --arg hash "${hash}" \
       '.hash = if .hash? then .hash else $hash end | .directory = (input_filename|split("/")|.[-2])' \
	$(realpath ${d})
done | {
    # always output an array, even when empty
    jq -s .
}
