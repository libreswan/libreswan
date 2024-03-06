#!/bin/sh

set -u

if test $# -gt 1; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 [ <earliest_commit> ]

Track KVM_RUTDIR's current branch and test each "interesting" commit.
Publish results under WEB_SUMMARYDIR.

EOF
    exit 1
fi

set -euvx

tester=$(realpath $0)
webdir=$(dirname ${tester})
benchdir=$(cd ${webdir}/../.. && pwd)
utilsdir=${benchdir}/testing/utils

# run from BENCHDIR so relative make varibles work
# and ./kvm doesn't get confused
cd ${benchdir}

make_variable() {
    local v=$(make -C ${benchdir}/testing/kvm --no-print-directory print-kvm-variable VARIABLE=$2)
    if test "${v}" == "" ; then
	echo $2 not defined 1>&2
	exit 1
    fi
    eval $1="'$v'"
}

make_variable rutdir KVM_RUTDIR
make_variable summarydir WEB_SUMMARYDIR
make_variable prefixes KVM_PREFIXES
make_variable workers KVM_WORKERS

rutdir=$(realpath ${rutdir})
summarydir=$(realpath ${summarydir})

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
    earliest_commit=$(${webdir}/gime-git-hash.sh ${rutdir} HEAD)
fi

json_status="${webdir}/json-status.sh --json ${summarydir}/status.json"
status=${json_status}

MAKE() {

    # So new features can be tested (?) use kvmrunner.py from this
    # directory (${utilsdir}), but point it at files in the test
    # directory (${rutdir}).

    runner="${utilsdir}/kvmrunner.py --publish-hash ${commit} --publish-results ${resultsdir} --testing-directory ${rutdir}/testing --publish-status ${summarydir}/status.json"

    make -C ${rutdir} $1 \
	    WEB_RESULTSDIR=
	    WEB_SUMMARYDIR=
	    KVM_PREFIXES="${prefixes}" \
	    KVM_WORKERS="${workers}" \
	    KVMRUNNER="${runner}"
}

KVM() {
    ${benchdir}/kvm ${target}
}

# start with basic status output; updated below to add more details as
# they become available.

update_status=${json_status}

# Update the repo.
#
# Time has passed (a run finished, woke up from sleep, or the script
# was restarted) so any new commits should be fetched.
#
# Force ${branch} to be identical to ${remote} by using --ff-only - if
# it fails the script dies.

${update_status} "updating repository"
git -C ${rutdir} fetch || true
git -C ${rutdir} merge --ff-only

# Update the summary web page
#
# This will add any new commits found in ${rutdir} (added by above
# fetch) and merge the results from the last test run.

${update_status} "updating summary"
make -C ${benchdir} web-summarydir \
     WEB_RESULTSDIR= \
     WEB_SUMMARYDIR=${summarydir}

# Select the next commit to test
#
# Search [earliest_commit..HEAD] for something interesting and
# untested.  If there's nothing interesting, sleep and then retry.

${update_status} "looking for work"
if ! commit=$(${webdir}/gime-work.sh ${summarydir} ${rutdir} ${earliest_commit}) ; then
    # Seemlingly nothing to do ...  github gets updated up every 15
    # minutes so sleep for less than that
    delay=$(expr 10 \* 60)
    now=$(date +%s)
    future=$(expr ${now} + ${delay})
    ${update_status} "idle; will retry at $(date -u -d @${future} +%H:%M) ($(date -u -d @${now} +%H:%M) + ${delay}s)"
    sleep ${delay}
    ${update_status} "restarting: ${tester}"
    exec ${tester}
fi

# Now discard everything back to the commit to be tested, making that
# HEAD.  This could have side effects such as switching branches, take
# care.
#
# When first starting and/or recovering this does nothing as the repo
# is already at head.

${update_status} "checking out ${commit}"
git -C ${rutdir} reset --hard ${commit}

# Determine the rutdir and add that to status.
#
# Mimic how web-targets.mki computes RESULTSDIR; switch to directory
# specific status.

resultsdir=${summarydir}/$(${webdir}/gime-git-description.sh ${rutdir})
gitstamp=$(basename ${resultsdir})
update_status="${update_status} --directory ${gitstamp}"

# create the resultsdir and point the summary at it.

rm -f ${summarydir}/current
ln -s $(basename ${resultsdir}) ${summarydir}/current

start_time=$(${webdir}/now.sh)
${update_status} "creating results directory"
make -C ${benchdir} web-resultsdir \
     WEB_TIME=${start_time} \
     WEB_HASH=${commit} \
     WEB_RESULTSDIR=${resultsdir} \
     WEB_SUMMARYDIR=${summarydir}

# fudge up enough of summary.json to fool the top level

${webdir}/json-summary.sh "${start_time}" > ${resultsdir}/summary.json

# Build / update / test the repo
#
# This list should match the hardwired list in results.html.  Should a
# table be generated?
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
# - the "~" suffix means ignore failure
#
# - the prefix MAKE: and KVM: denote what is run

targets="MAKE:distclean MAKE:html" # NATIVE!
finished=""

# form KVM:TARGET[~+]OS
oss="+fedora ~freebsd ~openbsd ~alpine ~debian"

if ${build_kvms} ; then
    for os in $oss ; do
	# i.e., kvm-upgrade[~+]OS
	targets="${targets} KVM:upgrade${os}"
    done
else
    targets="${targets} KVM:shutdown"
fi

for os in ${oss} ; do
    targets="${targets} KVM:transmogrify${os}"
done

targets="${targets} KVM:keys"

for os in ${oss} ; do
    targets="${targets} KVM:install${os}"
done

targets="${targets} KVM:check"

build_kvms=false # for next time round

# list of raw results; will be converted to an array

cp /dev/null ${resultsdir}/build.json.in

for t in ${targets} ; do

    # T=RUN:TARGET RUN:OT{,[~+]OS}
    run=$(    echo "${t}" | sed -e 's/\(.*\):\(\([^~+]*\)[~+]*\(.*\)\)/\1/' )
    target=$( echo "${t}" | sed -e 's/\(.*\):\(\([^~+]*\)[~+]*\(.*\)\)/\2/' -e 's/[~+]/-/' )
    ot=$(     echo "${t}" | sed -e 's/\(.*\):\(\([^~+]*\)[~+]*\(.*\)\)/\3/' )
    os=$(     echo "${t}" | sed -e 's/\(.*\):\(\([^~+]*\)[~+]*\(.*\)\)/\4/' )

    # ...~...
    ignore=$(expr "${t}" : '.*~' > /dev/null && echo true || echo false)

    finished="${finished} ${target}"
    logfile=${resultsdir}/${target}.log
    cp /dev/null ${logfile}

    # generate json of the progress
    {
	cat ${resultsdir}/build.json.in
	# same command further down
	jq --null-input \
	   --arg run    "${run}" \
	   --arg target "${target}" \
	   --arg ot     "${ot}" \
	   --arg os     "${os}" \
	   --arg status "running" \
	   '{ run: $run, target: $target, ot: $ot, os: $os, status: $status }'
    } | jq -s . > ${resultsdir}/build.json

    # run the target; note how the start of the pipeline
    # creates ${target}.ok as a way to detect success

    href="<a href=\"$(basename ${resultsdir})/${target}.log\">${target}</a>"
    ${status} "running '${run} ${href}'"

    if ${run} ${target} 2>&1 ; then
	touch ${resultsdir}/${target}.ok ;
    fi | tee -a ${resultsdir}/${target}.log

    if test -r ${resultsdir}/${target}.ok ; then
	result=ok
	case ${target} in
	    html )
		mkdir -p ${resultsdir}/documentation
		rm -f ${resultsdir}/documentation/*.html
		cp -v ${rutdir}/OBJ.*/html/*.html ${resultsdir}/documentation/
		# Use libreswan.7 as the index page since that
		# should be the starting point for someone reading
		# about libreswan.
		cp -v ${rutdir}/OBJ.*/html/libreswan.7.html ${resultsdir}/documentation/index.html
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
    gzip -v -9 ${resultsdir}/${target}.log

    ${status} "'${run} ${href}' ok"

    # generate json of the final result

    # same command further up
    {
	jq --null-input \
	   --arg run    "${run}" \
	   --arg target "${target}" \
	   --arg ot     "${ot}" \
	   --arg os     "${os}" \
	   --arg status "${result}" \
	   '{ run: $run, target: $target, ot: $ot, os: $os, status: $status }'
    } >> ${resultsdir}/build.json.in
    # convert raw list to an array
    jq -s . < ${resultsdir}/build.json.in > ${resultsdir}/build.json

    if test "${result}" = failed ; then
	# force the next run to test HEAD++ using rebuilt and updated
	# domains; hopefully that will contain the fix (or at least
	# contain the damage).
	${update_status} "${target} barfed, restarting with HEAD"
	exec ${tester}
    fi

done

# Eliminate any files in the repo and the latest results directory
# that are identical.
#
# Trying to do much more than this exceeds either hardlink's internal
# cache of checksums (causing hardlink opportunities to be missed); or
# the kernel's file cache (causing catatonic performance).
#
# It is assumed that git, when switching checkouts, creates new files,
# and not modifies in-place.

${update_status} "hardlink $(basename ${rutdir}) $(${resultsdir})"
hardlink -v ${rutdir} ${resultsdir}

# Check that the test VMs are ok
#
# A result with output-missing is good sign that the VMs have become
# corrupt and need a rebuild.

${update_status} "checking KVMs"
if grep '"output-missing"' "${resultsdir}/results.json" ; then
    ${update_status} "corrupt domains detected, restarting with HEAD"
    exec ${tester}
fi

# Clean out old logs
#
# The script can run for a long time before idleing so do this every
# time.  Never delete log files for -0- commits (i.e., releases).

${update_status} "deleting *.log.gz files older than 14 days"
find ${summarydir} \
     -type d -name '*-0-*' -prune \
     -o \
     -type f -name '*.log.gz' -mtime +14 -print0 | \
    xargs -0 --no-run-if-empty rm -v

exec ${tester} ${earliest_commit}
