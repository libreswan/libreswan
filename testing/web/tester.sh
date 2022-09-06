#!/bin/sh

set -u

if test $# -lt 2 -o $# -gt 3; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <repodir> <summarydir> [ <earliest_commit> ]

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

bindir=$(dirname $0)
makedir=$(cd ${bindir}/../.. && pwd)
utilsdir=${makedir}/testing/utils

# start with new shiny new just upgraded domains

kvm_setup="kvm-purge kvm-upgrade"

# Select the oldest commit to test.
#
# Will search [earliest_commit..HEAD] for something interesting and
# untested.
#
# When recovering from an error (and when just starting) set
# earliest_commit to HEAD so that only a new commit, which hopefully
# fixes the barf will be tested (if there's no new commit things go
# idle).
#
# If a commit was specified explicitly, start with that.

if test $# -gt 0 ; then
    # Could be a tag; gime-work.sh deals with that after the repo is
    # updated.
    earliest_commit=$1; shift
else
    earliest_commit=$(${bindir}/gime-git-hash.sh ${repodir} HEAD)
fi

json_status="${bindir}/json-status.sh --json ${summarydir}/status.json"
status=${json_status}


run() (
    href="<a href=\"$(basename ${resultsdir})/$1.log\">$1</a>"
    ${status} "running 'make ${href}'"

    # fudge up enough of summary.json to fool the top level
    if test ! -r ${resultsdir}/kvm-test.ok ; then
	${bindir}/json-summary.sh "${start_time}" > ${resultsdir}/summary.json
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
    # Search [earliest_commit..HEAD] for something interesting and
    # untested.

    ${status} "looking for work"
    if ! commit=$(${bindir}/gime-work.sh ${summarydir} ${repodir} ${earliest_commit}) ; then \
	# Seemlingly nothing to do ...

	# github gets updated up every 15 minutes so sleep for less
	# than that
	delay=$(expr 10 \* 60)
	now=$(date +%s)
	future=$(expr ${now} + ${delay})

	# do something productive
	${status} "idle; deleting debug.log.gz files older than 30 days"
	find ${summarydir} -type f -name 'debug.log.gz' -mtime +30 -print0 | \
	    xargs -0 --no-run-if-empty rm -v

	# is there still time?
	now=$(date +%s)
	if test ${future} -lt ${now} ; then
	    ${status} "the future (${future}) is now (${now})"
	    continue
	fi

	seconds=$(expr ${future} - ${now})
	${status} "idle; will retry at $(date -u -d @${future} +%H:%M) ($(date -u -d @${now} +%H:%M) + ${seconds}s)"
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

    resultsdir=${summarydir}/$(${bindir}/gime-git-description.sh ${repodir})
    gitstamp=$(basename ${resultsdir})
    status="${json_status} --directory ${gitstamp}"

    # create the resultsdir and point the summary at it.

    start_time=$(${bindir}/now.sh)
    ${status} "creating results directory"
    make -C ${makedir} web-resultsdir \
	 WEB_TIME=${start_time} \
	 WEB_REPODIR=${repodir} \
	 WEB_HASH=${commit} \
	 WEB_RESULTSDIR=${resultsdir} \
	 WEB_SUMMARYDIR=${summarydir}

    #
    # Clenup ready for the new run
    #

    ${status} "running distclean"
    run distclean

    #
    # Run the testsuite
    #
    # This list should match the hardwired list in results.html.
    # Should a table be generated?
    #
    # XXX: should run ./kvm
    #
    # ${kvm_setup} starts out as kvm-purge but then flips to
    # kvm-shutdown.  For kvm-purge, since it is only invoked when the
    # script is first changing and the REPO is at HEAD, the upgrade /
    # transmogrify it triggers will always be for the latest changes.

    targets=""
    finished=""

    # NOTE: kvm_setup={kvm-shutdown,kvm-purge}
    targets="${targets} ${kvm_setup}"
    kvm_setup=kvm-shutdown # for next time round

    targets="${targets} kvm-transmogrify kvm-keys"
    targets="${targets} kvm-install-fedora"
    # leading - means ignore failure; like make
    # targets="${targets} -kvm-install-freebsd"
    # targets="${targets} -kvm-install-openbsd"
    # targets="${targets} -kvm-install-netbsd"
    targets="${targets} kvm-check"

    # list of raw results; will be converted to an array
    cp /dev/null ${resultsdir}/build.json.in

    for t in ${targets} ; do

	# ignorable?
	target=$(expr "${t}" : '-\?\(.*\)')
	ignore=$(test "${target}" == "${t}" && echo false || echo true)
	finished="${finished} ${target}"
	logfile=${resultsdir}/${target}.log
	cp /dev/null ${logfile}

	# generate json of the progress
	{
	    cat ${resultsdir}/build.json.in
	    # same command further down
	    jq --null-input \
	       --arg target "${target}" \
	       --arg status running \
	       '{ target: $target, status: $status }'
	} | jq -s . > ${resultsdir}/build.json

	# run the target on hand
	if run ${target} ; then
	    result=ok
	elif ${ignore} ; then
	    # ex -kvm-install-openbsd = kvm-install-openbsd?
	    result=ignored
	else
	    result=failed
	fi

	# generate json of the final result

	# same command further up
	{
	    jq --null-input \
	       --arg target "${target}" \
	       --arg status "${result}" \
	       '{ target: $target, status: $status }'
	} >> ${resultsdir}/build.json.in
	# convert raw list to an array
	jq -s . < ${resultsdir}/build.json.in > ${resultsdir}/build.json

	if test "${status}" = failed ; then
	    # force the next run to test HEAD++ using rebuilt and
	    # updated domains; hopefully that will contain the fix (or
	    # at least contain the damage).
	    ${status} "${target} barfed, restarting with HEAD"
	    exec $0 ${repodir} ${summarydir}
	fi

    done

    # Eliminate any files in the repo and the latest results directory
    # that are identical.
    #
    # Trying to do much more than this exceeds either hardlink's
    # internal cache of checksums (causing hardlink opportunities to
    # be missed); or the kernel's file cache (causing catatonic
    # performance).
    #
    # It is assumed that git, when switching checkouts, creates new
    # files, and not modifies in-place.

    ${status} "hardlink $(basename ${repodir}) $(${resultsdir})"
    hardlink -v ${repodir} ${resultsdir}


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
