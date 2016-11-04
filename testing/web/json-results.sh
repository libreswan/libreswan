#!/bin/sh

set -eu

if test $# -lt 1; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ --json <json> ] <kvmresults-arg-or-test-result-or-results> ....

Generate results.json records on stdout using kvmresults.py.

If <json> is specified, write the results as a json array to that
file, else write raw json entries to stdout.

EOF
    exit 1
fi

json=""
if test "$1" = "--json"; then
    shift
    json=$1
    shift
fi

webdir=$(cd $(dirname $0) && pwd)
utilsdir=$(cd ${webdir}/../utils && pwd)
${utilsdir}/kvmresults.py \
	     --test-kind '' \
	     --test-result '' \
	     --json \
	     --print test-name,test-directory,start-time,end-time,host-names,saved-output-directory,output-directory,result,errors,runtime,total-time,boot-time,script-time,expected-result,baseline-output-directory \
	     "$@" | \
    if test -n "${json}" ; then
	jq -s '.' > ${json}.tmp
	mv ${json}.tmp ${json}
    else
	cat
    fi
