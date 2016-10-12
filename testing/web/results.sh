#!/bin/sh

set -eu

if test $# -lt 1; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <test-result-or-results> ....

Generate results.json records on stdout using kvmresults.py.

EOF
    exit 1
fi

webdir=$(cd $(dirname $0) && pwd)
utilsdir=$(cd ${webdir}/../utils && pwd)
${utilsdir}/kvmresults.py \
	     --test-kind '' \
	     --test-result '' \
	     --json \
	     --print test-name,test-directory,start-time,end-time,host-names,saved-output-directory,output-directory,result,errors,runtime,total-time,boot-time,script-time,expected-result,baseline-output-directory \
	     "$@" \
    | grep -v '^kvmresult'

# the grep gets around a bug where log lines end up in the output
