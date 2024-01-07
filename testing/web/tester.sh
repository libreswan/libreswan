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

webdir=$(dirname $0)
makedir=$(cd ${webdir}/../.. && pwd)
utilsdir=${makedir}/testing/utils

# start with new shiny new just upgraded domains

build_kvms=true

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
    earliest_commit=$(${webdir}/gime-git-hash.sh ${repodir} HEAD)
fi

json_status="${webdir}/json-status.sh --json ${summarydir}/status.json"
status=${json_status}


run() (
    href="<a href=\"$(basename ${resultsdir})/$1.log\">$1</a>"
    ${status} "running 'make ${href}'"

    # So new features can be tested (?) use kvmrunner.py from this
    # directory (${utilsdir}), but point it at files in the test
    # directory (${repodir}).

    runner="${utilsdir}/kvmrunner.py --publish-hash ${commit} --publish-results ${resultsdir} --testing-directory ${repodir}/testing --publish-status ${summarydir}/status.json"

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
    gzip -v -9 ${resultsdir}/$1.log
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
    if ! commit=$(${webdir}/gime-work.sh ${summarydir} ${repodir} ${earliest_commit}) ; then
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
	find ${summarydir} -type f -name '*.log.gz' -mtime +180 -print0 | \
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

    resultsdir=${summarydir}/$(${webdir}/gime-git-description.sh ${repodir})
    gitstamp=$(basename ${resultsdir})
    status="${json_status} --directory ${gitstamp}"

    # create the resultsdir and point the summary at it.

    rm -f ${summarydir}/current
    ln -s $(basename ${resultsdir}) ${summarydir}/current

    start_time=$(${webdir}/now.sh)
    ${status} "creating results directory"
    make -C ${makedir} web-resultsdir \
	 WEB_TIME=${start_time} \
	 WEB_REPODIR=${repodir} \
	 WEB_HASH=${commit} \
	 WEB_RESULTSDIR=${resultsdir} \
	 WEB_SUMMARYDIR=${summarydir}

    # fudge up enough of summary.json to fool the top level
    ${webdir}/json-summary.sh "${start_time}" > ${resultsdir}/summary.json

    #
    # Cleanup ready for the new run
    #

    ${status} "running distclean"
    if ! run distclean ; then
	${status} "distclean barfed, restarting with HEAD"
	exec $0 ${repodir} ${summarydir}
    fi

    #
    # Build / update / test the repo
    #
    # This list should match the hardwired list in results.html.
    # Should a table be generated?
    #
    # XXX: should run ./kvm
    #
    # - kvm-install triggers kvm-keys and kvm-install- et.al.,
    #   kvm-install-... so break each of these steps down.
    #
    # - make targets like upgrade explicit so it is clear where things
    #   fail
    #
    # - always transmogrify so current config is picked up
    #
    # - the "~" prefix to OS names means ignore failure; and "+ means
    #   it must pass

    targets="distclean html" # NATIVE!
    finished=""
    oss="+fedora ~freebsd ~netbsd ~openbsd ~alpine ~debian"

    if ${build_kvms} ; then
	targets="${targets} kvm-purge"
	for os in $oss ; do
	    # i.e., kvm-upgrade+OS and kvm-upgrade~OS
	    targets="${targets} kvm-upgrade${os}"
	    targets="${targets} kvm-transmogrify${os}"
	done
    else
	for os in $oss ; do
	    # i.e., kvm-shutdown+OS and kvm-shutdown~OS
	    targets="${targets} kvm-shutdown${os}"
	    targets="${targets} kvm-transmogrify${os}"
	done
    fi

    targets="${targets} kvm-keys"

    for os in ${oss} ; do
    	targets="${targets} kvm-install-all${os}"
    done

    targets="${targets} kvm-check"

    build_kvms=false # for next time round

    # list of raw results; will be converted to an array
    cp /dev/null ${resultsdir}/build.json.in

    for t in ${targets} ; do

	# "~" means ignore; "+" means pass
	target=$(echo "${t}" | tr '~+' '--')
	os=$(expr "${t}" : '^.*[~+]\(.*\)$' || echo -n)
	ot=$(expr "${t}" : '^\([^~+]*\)')
	ignore=$(expr "${t}" : '.*~' > /dev/null && echo true || echo false)
	finished="${finished} ${target}"
	logfile=${resultsdir}/${target}.log
	cp /dev/null ${logfile}

	# generate json of the progress
	{
	    cat ${resultsdir}/build.json.in
	    # same command further down
	    jq --null-input \
	       --arg target "${target}" \
	       --arg ot     "${ot}" \
	       --arg os     "${os}" \
	       --arg status "running" \
	       '{ target: $target, ot: $ot, os: $os, status: $status }'
	} | jq -s . > ${resultsdir}/build.json

	# run the target on hand
	if run ${target} ; then
	    result=ok
	    case ${target} in
		html )
		    mkdir -p ${resultsdir}/documentation
		    rm -f ${resultsdir}/documentation/*.html
		    cp -v ${repodir}/OBJ.*/html/*.html ${resultsdir}/documentation/
		    # Use libreswan.7 as the index page since that
		    # should be the starting point for someone reading
		    # about libreswan.
		    cp -v ${repodir}/OBJ.*/html/libreswan.7.html ${resultsdir}/documentation/index.html
		    ;;
		kvm-check )
		    # should only update when latest
		    rm -f ${summarydir}/latest
		    ln -s $(basename ${resultsdir}) ${summarydir}/latest
		    ;;
	    esac
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
	       --arg ot     "${ot}" \
	       --arg os     "${os}" \
	       --arg status "${result}" \
	       '{ target: $target, ot: $ot, os: $os, status: $status }'
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
