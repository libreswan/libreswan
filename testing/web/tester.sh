#!/bin/sh

if test $# -lt 2 -o $# -gt 3; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir> [ <hash> ]

Track <repodir>'s current branch and test each "interesting" commit.
Publish results under <summarydir>.

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

# start with new shiny domains

kvm_setup=kvm-purge

# Select the oldest commit to test.
#
# Will search [HEAD..oldest_commit] for something interesting and
# untested.
#
# When recovering from an error (and when just starting) set
# oldest_commit to HEAD so that only a new commit, which hopefully
# fixes, the barf will be tested (if there's no new commit things go
# idle).

oldest_commit=$(cd ${repodir} && git show --no-patch --format=%H HEAD)

# If a commit was specified explicitly, start with that.

if test $# -gt 0 ; then
    # could be a tag; convert after updating repo
    first_test_commit=$1; shift
else
    first_test_commit=
fi

json_status="${webdir}/json-status.sh --json ${summarydir}/status.json"
status=${json_status}


run() (
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
)

while true ; do

    # start with basic status

    status=${json_status}

    # Update the repo.
    #
    # Time has passed (a run finished, woke up from sleep, or the
    # script was restarted) so any new commits should be fetched.
    #
    # Force ${branch} to be identical to ${remote} by using --ff-only
    # - if it fails the script dies.

    ${status} "updating repository"
    ( cd ${repodir} && git fetch || true )
    ( cd ${repodir} && git merge --ff-only )

    # Update the summary web page
    #
    # This will add any new commits found in ${repodir} (added by
    # above fetch) and merge the results from the last test run.

    ${status} "updating summary"
    make -C ${makedir} web-summarydir \
	 WEB_REPODIR=${repodir} \
	 WEB_RESULTSDIR= \
	 WEB_SUMMARYDIR=${summarydir}

    # Select the next commit to test
    #
    # Search [HEAD..oldest_commit] for something interesting and
    # untested.

    ${status} "looking for work"
    if test "${first_test_commit}" != "" ; then
	# Use ^{} + rev-parse to convert the potentially signed tag
	# into the hash that the tag is refering to.  Without ^{}
	# rev-parse returns the hash of the tag.
	commit=$(cd ${repodir} && git rev-parse ${first_test_commit}^{})
	first_test_commit=
    elif ! commit=$(${webdir}/gime-work.sh ${summarydir} ${repodir} ${oldest_commit}) ; then \
	# Seemlingly nothing to do; github gets updated up every 15
	# minutes so sleep for less than that
	seconds=$(expr 10 \* 60)
	now=$(date +%s)
	future=$(expr ${now} + ${seconds})
	${status} "idle; will retry $(date -u -d @${future} +%H:%M)"
	sleep ${seconds}
	continue
    fi

    # Now discard everything back to the commit to be tested, making
    # that HEAD.  This could have side effects such as switching
    # branches, take care.
    #
    # When first starting and/or recovering this does nothing as the
    # repo is already at head.

    ${status} "checking out ${commit}"
    ( cd ${repodir} && git reset --hard ${commit} )

    # Mimic how web-targets.mki computes RESULTSDIR; switch to
    # directory specific status.

    resultsdir=${summarydir}/$(${webdir}/gime-git-description.sh ${repodir})
    gitstamp=$(basename ${resultsdir})
    status="${json_status} --directory ${gitstamp}"

    # create the resultsdir and point the summary at it.

    start_time=$(${webdir}/now.sh)
    ${status} "creating results directory"
    make -C ${makedir} web-resultsdir \
	 WEB_TIME=${start_time} \
	 WEB_REPODIR=${repodir} \
	 WEB_HASH=${commit} \
	 WEB_RESULTSDIR=${resultsdir} \
	 WEB_SUMMARYDIR=${summarydir}

    # Run the testsuite
    #
    # This list should match results.html.  Should a table be
    # generated?
    #
    # ${kvm_setup} starts out as kvm-purge but then filps to
    # kvm-shutdown.  For kvm-purge, since it is only invoked when the
    # script is first changing and the REPO is at HEAD, the upgrade /
    # transmogrify it triggers will always be for the latest changes.

    targets="distclean ${kvm_setup} kvm-keys kvm-install kvm-test"
    kvm_setup=kvm-shutdown
    for target in ${targets}; do
	# generate json of the progress
	touch ${resultsdir}/${target}.log
	${webdir}/json-make.sh --json ${resultsdir}/make.json --resultsdir ${resultsdir} ${targets}
	# run the target on hand
	if ! run ${target} ; then
	    # force the next run to test HEAD++ using rebuilt and
	    # updated domains; hopefully that will contain the fix (or
	    # at least contain the damage).
	    ${status} "${target} barfed, restarting with HEAD"
	    exec $0 ${repodir} ${summarydir}
	fi
    done

    # Check that the test VMs are ok
    #
    # A result with output-missing is good sign that the VMs have
    # become corrupt and need a rebuild.

    ${status} "checking KVMs"
    if grep '"output-missing"' "${resultsdir}/results.json" ; then
	${status} "corrupt domains detected, restarting with HEAD"
	exec $0 ${repodir} ${summarydir}
    fi

    # loop back to code updating summary dir

done
