#!/bin/sh

set -eu

if test "$#" -lt 2; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <rutdir> [- | <summary.json> ...]

Using <rutdir> (to map the abbreviated hash in the result directory
name onto a full hash) merge the <summary.json> files into a single
summaries.json on STDOUT.

'-' indicates the list of summary.json files is on stdin.

The test output is left unchanged.

EOF
    exit 1
fi

bindir=$(cd $(dirname $0) && pwd)

rutdir=$(cd $1 && pwd) ; shift

if test $# -eq 1 -a x"$1" = x"-" ; then
    cat
else
    for d in "$@"; do
	echo "$d"
    done
fi | while read d; do
    dir=$(dirname $d)
    rev=$(${bindir}/gime-git-rev.sh ${dir})
    # expand to full hash
    hash=$(${bindir}/gime-git-hash.sh ${rutdir} ${rev})
    # let any existing hash override above
    jq --arg hash "${hash}" \
       '.hash = if .hash? then .hash else $hash end | .directory = (input_filename|split("/")|.[-2])' \
	$(realpath ${d})
done | {
    # always output an array, even when empty
    jq -s .
}
