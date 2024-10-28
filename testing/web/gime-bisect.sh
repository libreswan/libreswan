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

echo 'creating a list of all tests'

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

echo 'merge ${run}/${test}/OUTPUT/result.json into ${test}.json'

while read test ; do
    echo $test
    {
	find ${summarydir} \
	     -name ${test} \
	     -printf '%h/%f/OUTPUT/result.json\n'
    } | {
	xargs cat
    } | {
	jq -s
    } > ${bisectdir}/${test}.json
done < ${bisectdir}/tests.tmp

echo 'merge ${run}/results.json'

{
    find ${summarydir} -name bisect -prune -o -name results.json -print | while read results ; do
	echo $results 1>&2
	rundir=$(dirname ${results})
	{
	    cat ${results}
	} | {
	    jq '.[]'
	} | {
	    jq --arg rundir "$(realpath --relative-to ${bisectdir} ${rundir})" \
	       '. + { rundir: $rundir }'
	}
    done
} | {
    jq -s
} | {
    jq 'reduce .[] as $d (null; .[$d.test_name] += [{ result: $d.result, rundir: $d.rundir, date: $d.start_time }])'
} > ${bisectdir}/all.json # NOT RESULTS>JSON see find above
