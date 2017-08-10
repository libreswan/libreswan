#!/bin/sh

if test $# -lt 1; then
    cat <<EOF >/dev/stderr

Usage:

    $0 <path-to-alg-parse> [ | patch -p1 ]

Piping to patch will apply the reported differences.

EOF
    exit 1
fi

algparse=$1 ; shift
dir=$(dirname $0)
export EF_DISABLE_BANNER=1
set -e

rc=0
while read file flags ; do
    if test -r ${dir}/${file} ; then
	if ${algparse} ${flags} 2>&1 \
	       | sed -e "s;^${algparse};algparse;" \
	       | diff -u ${dir}/${file} - ; then
	    :
	else
	    rc=1
	fi
    else
	${algparse} ${flags} 2>&1 \
	    | sed -e "s;${algparse};algparse;" \
	    | tee ${dir}/${file}.tmp
	echo created ${dir}/${file}.tmp 1>&2
	rc=1
    fi
done <<EOF
algparse.v.txt -v -t
algparse.v1.txt -v1 -t
algparse.v2.txt -v2 -t
algparse.fips.v.txt -fips -v -t
algparse.fips.v1.txt -fips -v1 -t
algparse.fips.v2.txt -fips -v2 -t
EOF

exit ${rc}
