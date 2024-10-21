#!/bin/sh

set -eu

if test "$#" -lt 1; then
    cat >>/dev/stderr <<EOF

Usage:
   $0 <summarydir>
EOF
    exit 1
fi

bindir=$(cd $(dirname $0) && pwd)

summarydir=$1 ; shift
testsdir=${summarydir}/tests/

find ${testsdir} -name '*.tmp' -print | xargs --no-run-if-empty rm

find ${summarydir} -name result.json | while read result ; do
    outputdir=$(dirname ${result})
    testdir=$(dirname ${outputdir})
    test=$(basename ${testdir})
    rundir=$(dirname ${testdir})
    # path is relative to ${tests}
    cat ${result} \
	| jq --arg rundir $(realpath --relative-to ${testsdir} ${rundir}) \
	     '. + { rundir: $rundir }' \
	     >> ${testsdir}/${test}.tmp
done

# results for each test
find ${testsdir} -name '*.tmp' -print | while read results ; do
    test=$(basename ${results} .tmp)
    jq -s < ${results} > ${testsdir}/${test}.json
done

# list of all tests
find ${testsdir} -name '*.tmp' -print | while read results ; do
    test=$(basename ${results} .tmp)
    echo '{ "test": "'"${test}"'" }'
done | jq -s > ${testsdir}/tests.json
