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
    test=
    case "${file}" in
	*-fips* ) flags="${flags} -fips" ;;
    esac

    for opt in $(basename ${file} | sed -e 's/\./ /g'); do
	case "${opt}" in
	    v1 ) flags="${flags} -v1" test="-t" ;;
	    v2 ) flags="${flags} -v2" test="-t" ;;
	    pfs ) flags="${flags} -pfs" test="-t" ;;
	    v ) test="-v" ;;
	esac
    done
    flags="${flags} ${test}"

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
