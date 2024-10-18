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

declare -A makeflags # Associative

tester=$(realpath $0)
benchdir=$(realpath $(dirname ${tester})/../..)

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

make_variable branch_name KVM_BRANCH_NAME
make_variable branch_tag KVM_BRANCH_TAG
make_variable rutdir KVM_RUTDIR
make_variable summarydir KVM_WEBDIR
make_variable KVM_PREFIX KVM_PREFIX
make_variable KVM_WORKERS KVM_WORKERS
# what could build
make_variable KVM_PLATFORM KVM_PLATFORM
# what must build / is enabled
make_variable KVM_OS KVM_OS

rutdir=$(realpath ${rutdir})
webdir=$(realpath ${summarydir})

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
    earliest_commit=$(git -C ${rutdir} show --no-patch --format=%H HEAD --)
fi

# start with basic status output; updated below to add more details as
# they become available.

json_status="${benchdir}/testing/web/json-status.sh --json ${summarydir}/status.json"
update_status=${json_status}

MAKE() {
    make -C ${rutdir} $1 \
	    WEB_RESULTSDIR=
	    WEB_SUMMARYDIR=
}

KVM() {
    ${benchdir}/kvm ${target} "${makeflags[@]}" \
	       WEB_TIME=${start_time} \
	       WEB_HASH=${commit} \
	       WEB_RESULTSDIR=${resultsdir} \
	       WEB_SUMMARYDIR=${summarydir}
}

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

if ! commit=$(${benchdir}/testing/web/gime-work.sh ${summarydir} ${rutdir} ${earliest_commit}) ; then
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

count=$(git -C ${rutdir} rev-list --count ${branch_tag}..${commit})
abbrev=$(git -C ${rutdir} show --no-patch --format="%h" ${commit})
gitstamp=${branch_name}-${count}-g${abbrev}

${update_status} "checking out ${commit} (${gitstamp})"

git -C ${rutdir} reset --hard ${commit}

# Add the results dir to status.

resultsdir=${summarydir}/${gitstamp}
update_status="${update_status} --directory ${gitstamp}"

# create the resultsdir and point the summary at it.

${update_status} "creating results directory"

rm -f ${summarydir}/current
ln -s $(basename ${resultsdir}) ${summarydir}/current

start_time=$(${benchdir}/testing/web/now.sh)
make -C ${benchdir} web-resultsdir \
     WEB_TIME=${start_time} \
     WEB_HASH=${commit} \
     WEB_RESULTSDIR=${resultsdir} \
     WEB_SUMMARYDIR=${summarydir}

# fudge up enough of summary.json to fool the top level

${benchdir}/testing/web/json-summary.sh "${start_time}" > ${resultsdir}/summary.json

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

build_json()
{
    local run=$1
    local target=$2
    local ot=$3
    local os=$4
    local status=$5
    jq --null-input \
       --arg run    "${run}" \
       --arg target "${target}" \
       --arg ot     "${ot}" \
       --arg os     "${os}" \
       --arg status "${status}" \
       '{ run: $run, target: $target, ot: $ot, os: $os, status: $status }'
}

run_target()
{

    local run=$1
    local target=$2
    local ot=$3
    local os=$4
    local ignore=$5

    finished="${finished} ${target}"
    logfile=${resultsdir}/${target}.log
    cp /dev/null ${logfile}

    # Update build.json
    #
    # Merge build.json.in and the current build command into
    # build.json.

    {
	cat ${resultsdir}/build.json.in
	build_json "${run}" "${target}" "${ot}" "${os}" "running"
    } | jq -s . > ${resultsdir}/build.json

    # Update the status.

    href="<a href=\"$(basename ${resultsdir})/${target}.log\">${target}</a>"
    ${update_status} "running '${run} ${href}'"

    # Run the target
    #
    # Notice how the first stage of the pipeline saves it's status
    # touching ${target}.ok.

    if ${run} ${target} 2>&1 ; then
	touch ${resultsdir}/${target}.ok ;
    fi | tee -a ${resultsdir}/${target}.log

    # Figure out and save the the result.

    if test -r ${resultsdir}/${target}.ok ; then
	result=ok
    elif ${ignore} ; then
	# for instance, OpenBSD build fail is ignored.
	result=ignored
    else
	result=failed
    fi

    # handle any magic extra processing

    case ${result}:${target} in
	ok:html )
	    mkdir -p ${resultsdir}/documentation
	    rm -f ${resultsdir}/documentation/*.html
	    cp -v ${rutdir}/OBJ.*/html/*.html ${resultsdir}/documentation/
	    # Use libreswan.7 as the index page since that
	    # should be the starting point for someone reading
	    # about libreswan.
	    cp -v ${rutdir}/OBJ.*/html/libreswan.7.html ${resultsdir}/documentation/index.html
	    ;;
	ok:check )
	    # should also only update latest when most recent
	    # commit; how?
	    rm -f ${summarydir}/latest
	    ln -s $(basename ${resultsdir}) ${summarydir}/latest
	    ;;
    esac

    # Maintain a list of KVM_$(OS)={true,false} flags.  These are to
    # to ./kvm which passes them onto MAKE controlling which OS
    # platforms are and are not enabled.

    if test -n "${os}" ; then
	if test "${result}" = ok ; then
	    makeflags[${os}]="KVM_${os^^}=true"
	else
	    makeflags[${os}]="KVM_${os^^}=false"
	fi
    fi

    gzip -v -9 ${resultsdir}/${target}.log

    # Update the status: done.

    ${update_status} "'${run} ${href}' ok"

    # Update build.json.
    #
    # This time add the result to build.json.in and built build.json
    # from that.

    build_json  "${run}" "${target}" "${ot}" "${os}" "${result}" >> ${resultsdir}/build.json.in
    jq -s . < ${resultsdir}/build.json.in > ${resultsdir}/build.json

    if test "${result}" = failed ; then
	# force the next run to test HEAD++ using rebuilt and updated
	# domains; hopefully that will include the fix (or at least
	# contain the damage).
	${update_status} "${target} barfed, restarting with HEAD: ${tester}"
	exec ${tester}
    fi
}

targets="MAKE:distclean MAKE:html" # NATIVE!
finished=""

if ${build_kvms} ; then
    for platform in ${KVM_PLATFORM} ; do
	# i.e., kvm-upgrade[~+]OS
	targets="${targets} KVM:upgrade~${platform}"
    done
else
    targets="${targets} KVM:shutdown"
fi

for platform in ${KVM_PLATFORM} ; do
    targets="${targets} KVM:transmogrify~${platform}"
done

targets="${targets} KVM:keys"

for platform in ${KVM_PLATFORM} ; do
    # anything in OSS must build
    case " ${KVM_OS} " in
	"* ${platform} *" )
	    targets="${targets} KVM:install+${platform}"
	    ;;
	* )
	    targets="${targets} KVM:install~${platform}"
	    ;;
    esac
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

    run_target "${run}" "${target}" "${ot}" "${os}" "${ignore}"

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
    ${update_status} "corrupt domains detected, restarting with HEAD: ${tester}"
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

${update_status} "restarting: ${tester} ${earliest_commit}"

exec ${tester} ${earliest_commit}
