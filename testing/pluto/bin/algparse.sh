#!/bin/sh

if test $# -lt 1; then
    cat <<EOF >/dev/stderr

Usage:

    $0 <path-to-alg-parse> [ <test-files> ] [ | patch -p1 ]

Piping to patch will apply the reported differences.

EOF
    exit 1
fi

export EF_DISABLE_BANNER=1

algparse=$1 ; shift
if test $# -eq 0 ; then
    dir=$(dirname $(dirname $0))

    set - ${dir}/algparse-*/algparse.*.txt
fi

set -e

rc=0
for file in "$@" ; do

    flags=
    case "${file}" in
	*-fips* ) flags="${flags} -fips" ;;
    esac

    case "${file}" in
	*.v1.* ) flags="${flags} -v1 -t" ;;
	*.v2.* ) flags="${flags} -v2 -t" ;;
	*.v.* ) flags="${flags} -v" ;;
    esac

    echo ${algparse} ${flags} \# ${file} 1>&2

    if test -r ${file} ; then
	if ${algparse} ${flags} 2>&1 \
	       | sed -e "s;^${algparse};algparse;" \
	       | diff -u ${file} - ; then
	    :
	else
	    rc=1
	fi
    else
	${algparse} ${flags} 2>&1 \
	    | sed -e "s;${algparse};algparse;" \
	    | tee ${file}
	echo created ${dir}/${file} 1>&2
	rc=1
    fi
done

exit ${rc}
