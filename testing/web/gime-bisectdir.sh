#!/bin/sh

set -eu

if test "$#" -lt 1; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <summarydir> [ <test-result> }

Create the directory bisect/ containing json dumps of each test's
results.  In theory can be used to bisect a test.

EOF
    exit 1
fi

bindir=$(realpath $(dirname $0))

summarydir=$(realpath $1) ; shift
bisectdir=${summarydir}/bisect


echo 'cleaning out previous run'


find ${bisectdir} -name '*.tmp' -print | xargs --no-run-if-empty rm


echo 'creating a list of all test runs'

{
    {
	# ${summarydir}/${run}/summary.json
	find ${summarydir} \
	     -name summary.json \
	     -printf '%h\n'
    } | {
	sed -e 's;.*/;;'
    } | {
	sort -V
    } > ${bisectdir}/runs.tmp
    jq -R < ${bisectdir}/runs.tmp | jq -s > ${bisectdir}/runs.json
}

echo 'creating a list of all tests'

{
    {
	find ${summarydir} \
	     -name results.json \
	     -print
    } | {
	xargs jq -r '.[].test_name'
    } | {
	sort -u
    } > ${bisectdir}/tests.tmp
    jq -R < ${bisectdir}/tests.tmp | jq -s > ${bisectdir}/tests.json
}

echo 'merge ${summarydir}/${rundir}/${testdir}/OUTPUT/result.json into ${test}.json'

{
    while read testdir ; do
	echo -n "${testdir} " 1>&1
	while read rundir ; do
	    result=${summarydir}/${rundir}/${testdir}/OUTPUT/result.json
	    if test -r ${result} ; then
		echo -n "+" 1>&2
		jq --arg rundir "${rundir}" \
		   '. + { run: $rundir }' \
		   < ${result}
	    else
		echo -n "-" 1>&2
		echo '{ "run": "'"${rundir}"'" }'
	    fi
	done < ${bisectdir}/runs.tmp > ${bisectdir}/${testdir}.tmp
	jq -s \
	   < ${bisectdir}/${testdir}.tmp \
	   > ${bisectdir}/${testdir}.json
	echo 1>&2
    done < ${bisectdir}/tests.tmp
}

echo merging into all.json

{
    {
	jq '{ tests: . }' < ${bisectdir}/tests.json
	jq '{ runs: . }' < ${bisectdir}/runs.json
	while read testdir ; do
	    # array of results
	    jq 'reduce .[] as $d ([]; . += [$d.result] )' \
	       < ${bisectdir}/${testdir}.json
	done < ${bisectdir}/tests.tmp | jq -s '{ results: . }'
    } > ${bisectdir}/all.tmp
    jq -s 'add' \
       < ${bisectdir}/all.tmp \
       > ${bisectdir}/all.json
}
