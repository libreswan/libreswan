#!/bin/sh

if test $# -lt 2 -o $# -gt 3; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir> [ <first-commit> ]

Track <repodir>'s current branch and test each "interesting" commit.
Publish results under <summarydir>.

If <first-commit> is specified, then only go back as far as that
commit when looking for work.  Default is to use <repodir>s current
HEAD as the earliest commit.

XXX: Should this also look at and use things like WEB_PREFIXES and
WEB_WORKERS in Makefile.inc.local?

EOF
    exit 1
fi

set -euvx

repodir=$(cd $1 && pwd ) ; shift
summarydir=$(cd $1 && pwd) ; shift

webdir=$(dirname $0)
makedir=$(cd ${webdir}/../.. && pwd)
utilsdir=${makedir}/testing/utils

# By default, only test new commits.
if test $# -gt 0 ; then
    first_commit=$1 ; shift
else
    first_commit=HEAD
fi
first_commit=$(cd ${repodir} && git show --no-patch --format=%H ${first_commit})

status() {
    ${webdir}/json-status.sh --json ${summarydir}/status.json "$@"
    cat <<EOF

--------------------------------------

    $*

--------------------------------------

EOF
}

run() {
    href="<a href=\"$(basename ${resultsdir})/$1.log\">$1</a>"
    ${status} "running 'make ${href}'"

    # fudge up enough of summary.json to fool the top level
    if test ! -r ${resultsdir}/kvm-test.ok ; then
	${webdir}/json-summary.sh "${start_time}" > ${resultsdir}/summary.json
    fi

    # So new features can be tested (?) use kvmrunner.py from this
    # directory (${utilsdir}), but point it at files in the test
    # directory (${repodir}).

    runner="${utilsdir}/kvmrunner.py --publish-hash ${commit} --publish-results ${resultsdir} --testing-directory ${repodir}/testing --publish-status ${summarydir}/status.json"

    # Use trick to both capture the status of make and tee output to a
    # log file.

    if make -C ${repodir} $1 \
	    WEB_REPODIR= \
	    WEB_RESULTSDIR= \
	    WEB_SUMMARYDIR= \
	    ${runner:+KVMRUNNER="${runner}"} \
	    ${prefixes:+KVM_PREFIXES="${prefixes}"} \
	    ${workers:+KVM_WORKERS="${workers}"} \
	    2>&1 ; then
	touch ${resultsdir}/$1.ok ;
    fi | tee -a ${resultsdir}/$1.log
    if test ! -r ${resultsdir}/$1.ok ; then
	${status} "'make ${href}' failed"
	exit 1
    fi

}

while true ; do

    # Check that the test VMs are ok
    #
    # A result with output-missing is good sign that the VMs have
    # become corrupt and need a rebuild.

    status "checking KVMs"
    if grep '"output-missing"' "${summarydir}"/*-g*/results.json ; then
	status "corrupt domains detected, deleting old"
	( cd ${repodir} && make kvm-purge )
	status "corrupt domains detected, deleting bogus results"
	grep '"output-missing"' "${summarydir}"/*-g*/results.json \
	    | sed -e 's;/results.json.*;;' \
	    | sort -u \
	    | xargs --max-args=1 --verbose --no-run-if-empty rm -rf
	status "corrupt domains detected, building fresh domains"
	( cd ${repodir} && make kvm-install-test-domains )
    fi

    # Update the repo.
    #
    # Time has passed (a run finished, woke up from sleep, or the
    # script was restarted) so any new commits should be fetched.
    #
    # Force ${branch} to be identical to ${remote} by using --ff-only
    # - if it fails the script dies.

    status "updating repo"
    ( cd ${repodir} && git fetch || true )
    ( cd ${repodir} && git merge --ff-only )

    # Update the summary web page
    #
    # This will add any new commits found in ${repodir} (added by
    # above fetch) and merge the results from the last test run.

    status "updating summary"
    make -C ${makedir} web-summarydir \
	 WEB_REPODIR=${repodir} \
	 WEB_RESULTSDIR= \
	 WEB_SUMMARYDIR=${summarydir}

    # find something to do
    #
    # If there is nothing to do then sleep for a bit.

    status "looking for work"
    if ! commit=$(${webdir}/gime-work.sh ${summarydir} ${repodir} ${first_commit}) ; then \
	# Seemlingly nothing to do; github gets updated up every 15
	# minutes so sleep for less than that
	seconds=$(expr 10 \* 60)
	now=$(date +%s)
	future=$(expr ${now} + ${seconds})
	status "idle; will retry $(date -u -d @${future} +%H:%M)"
	sleep ${seconds}
	continue
    fi

    # Now discard everything back to the commit to be tested, making
    # that HEAD.  This could have side effects such as switching
    # branches, take care.

    status "checking out ${commit}"
    ( cd ${repodir} && git reset --hard ${commit} )

    # Mimic how web-targets.mki computes RESULTSDIR.

    resultsdir=${summarydir}/$(${webdir}/gime-git-description.sh ${repodir})
    gitstamp=$(basename ${resultsdir})
    status="${webdir}/json-status.sh \
      --json ${summarydir}/status.json \
      --directory ${gitstamp}"

    # create the resultsdir and point the summary at it.

    start_time=$(${webdir}/now.sh)
    ${status} "creating results directory"
    make -C ${makedir} web-resultsdir \
	 WEB_TIME=${start_time} \
	 WEB_REPODIR=${repodir} \
	 WEB_HASH=${commit} \
	 WEB_RESULTSDIR=${resultsdir} \
	 WEB_SUMMARYDIR=${summarydir}

    # run the testsuite

    run kvm-shutdown
    run distclean
    run kvm-install
    run kvm-keys
    run kvm-test

    # loop back to code updating summary dir

done
