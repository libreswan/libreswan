#!/bin/sh

if test $# -lt 1; then
    cat <<EOF >/dev/stderr
Usage: $0 <path-to-alg-parse>
EOF
    exit 1
fi

algparse=$1 ; shift
dir=$(dirname $0)

set -e

while read file flags ; do
    if test -r ${dir}/${file} ; then
	${algparse} ${flags} 2>&1 | sed -e "s;^${algparse};algparse;" | diff -u ${dir}/${file} -
    else
	${algparse} ${flags} 2>&1 | sed -e "s;${algparse};algparse;" | tee ${dir}/${file}.tmp
	echo created ${dir}/${file}.tmp 1>&2
	exit 1
    fi
done <<EOF
algparse.v.txt -v
algparse.v1.txt -v1
algparse.v2.txt -v2
algparse.fips.v.txt -fips -v
algparse.fips.v1.txt -fips -v1
algparse.fips.v2.txt -fips -v2
EOF
