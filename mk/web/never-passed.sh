#!/bin/sh

set -eu

output="<expectation> <nr-passed> <nr-failed> <runs-since-pass> <runs-since-fail> <total-runs> <test>"
if test $# -ne 1 ; then
    cat <<EOF >/dev/stderr

Usage:

    $0 <results-directory>

List some test stats in the form:

    ${output}

EOF

    exit 1
fi

cd $1

# Create a list of completed test runs in reverse version order (i.e.,
# latest version is first).  Presumably only completed test runs have
# the TESTLIST file.

runs=$(find . -name TESTLIST -print -prune | cut -d/ -f2 | sort -V -r)

# Use the TESTLIST from the most recent complete test run (use
# status.json to exclude the current test run).

TESTLIST=
for run in ${runs} ; do
    if grep "\"${run}\"" status.json; then
	echo "Skipping ${run}" 1>&2
    else
	TESTLIST=${run}/TESTLIST
	break;
    fi
done
if test -z "${TESTLIST}" ; then
    echo TESTLIST not found 1>&2
    exit 1
fi

# Drop some hints on how to use the output.

hints() {
    cat <<EOF 1>&2
Using ${TESTLIST}
${output}
sort -k 2,2n -k 6,6nr
EOF
}

hints

while read kind test expectation junk ; do
    case "${kind}" in
	kvmplutotest ) ;;
	* ) continue ;;
    esac
    nr_passed=0
    nr_failed=0
    total_runs=0
    runs_since_fail=
    runs_since_pass=
    for run in ${runs} ; do
	result=${run}/${test}/OUTPUT/RESULT
	if test ! -r ${result} ; then
	    # missing is treated like a fail; probably when the test
	    # was added.
	    continue
	fi
	total_runs=$((${total_runs} + 1))
	if grep -e '"result" *: *"passed"' < ${result} > /dev/null ; then
	    nr_passed=$((${nr_passed} + 1))
	    if test "${runs_since_pass}" = ""; then
		runs_since_pass=$((${total_runs} - 1))
	    fi
	else
	    nr_failed=$((${nr_failed} + 1))
	    if test "${runs_since_fail}" = ""; then
		runs_since_fail=$((${total_runs} - 1))
	    fi
	fi
    done
    if test "${runs_since_pass}" = ""; then
	runs_since_pass=${total_runs}
    fi
    if test "${runs_since_fail}" = ""; then
	runs_since_fail=${total_runs}
    fi
    # output in a format that is friendly to commands like 'sort -n -r'
    # and 'sort -k 1n -k 3nr'
    echo ${expectation} ${nr_passed} ${nr_failed} ${runs_since_pass} ${runs_since_fail} ${total_runs} ${test}
done < ${TESTLIST}

hints
