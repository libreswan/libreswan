#!/bin/sh

set -eu

if test "$#" -lt 3; then
    cat >>/dev/stderr <<EOF

Usage:

   $0 <repodir> <testsdir(output)> <rundir> ...

Using <repodir> (to map the abbreviated hash in the result directory
name onto a full hash?) merge the test results under <rundir> into
results for each individual test writing them into <testdir>.

The test output is left unchanged.

EOF
    exit 1
fi

bindir=$(cd $(dirname $0) && pwd)

repodir=$(cd $1 && pwd) ; shift
testsdir=$(cd $1 && pwd) ; shift

for rundir in "$@"; do

    run=$(basename ${rundir})

    rev=$(${bindir}/gime-git-rev.sh ${rundir})
    hash=$(${bindir}/gime-git-hash.sh ${repodir} ${rev})
    if test "${hash}" = "" ; then
	hash=null
    fi

    echo ${run} ${hash} 1>&2

    {
	cd ${rundir}
	find . \
	     -maxdepth 4 \
	     -type f \
	     -name result.json \
	     -print
    } | {
	# ./${testdir}/OUTPUT/result.json
	cut -d/ -f2
    } | while read testdir ; do
	# echo ${testsdir}/${testdir}/${run}.json 1>&2
	mkdir -p ${testsdir}/${testdir}
	# let any existing hash override above
	jq --arg hash "${hash}" --arg run "${run}" \
	   '.hash = if .hash? then .hash else $hash end | .run = $run' \
	   ${rundir}/${testdir}/OUTPUT/result.json \
	   > ${testsdir}/${testdir}/${run}.json
    done
done

echo joining 1>&2

cd ${testsdir}
{
    find . \
	 -maxdepth 1 \
	 -type d \
	 -print
} | {
     cut -d/ -f2
} | while read testdir ; do
    find ${testdir} -name '*.json' -print \
	| xargs cat \
	| jq --slurp . - > ${testdir}.json
done

exit 0
