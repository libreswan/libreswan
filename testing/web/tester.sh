#!/bin/sh

set -ue

if test $# -gt 0; then
    cat >> /dev/stderr <<EOF

Usage:

    $0

Track KVM_RUTDIR's current branch and test each "interesting" commit.
Publish results under WEB_SUMMARYDIR.

EOF
    exit 1
fi

echo args: "$@"

tester=$(realpath $0)
bindir=$(dirname ${tester})
web_makedir=$(dirname ${tester})
benchdir=$(realpath $(dirname ${tester})/../..)

# run from BENCHDIR so relative make varibles work
# and ./kvm doesn't get confused
cd ${benchdir}

make_kvm_variable() {
    local v=$(make -C ${benchdir}/testing/kvm \
		   --no-print-directory \
		   print-kvm-variable \
		   VARIABLE=$2)
    if test "${v}" == "" ; then
	echo $2 not defined 1>&2
	exit 1
    fi
    eval $1="'$v'"
    echo "$1=$v"
}

make_web_variable() {
    local v=$(make -C ${bindir} \
		   --no-print-directory \
		   print-web-variable \
		   VARIABLE=$2)
    if test "${v}" == "" ; then
	echo $2 not defined 1>&2
	exit 1
    fi
    eval $1="'$v'"
    echo $1=$v
}

NOW()
{
    date --utc --iso-8601=seconds
}

RESTART()
{
    STATUS "restarting: $@; sending output to ${summarydir}/tester.log"
    exec ${tester} >> ${summarydir}/tester.log 2>&1 < /dev/null
}

STATUS()
{
    ${bindir}/json-status.sh \
	       --json ${summarydir}/status.json \
	       ${subdir:+--directory ${subdir}} \
	       "$*"
    echo "$*" >> ${summarydir}/tester.log
}

RUN()
(
    echo "running: $*" >> ${summarydir}/tester.log
    set -x
    "$@"
)

make_kvm_variable rutdir        KVM_RUTDIR
make_kvm_variable prefix        KVM_PREFIX
make_kvm_variable workers       KVM_WORKERS
make_kvm_variable kvm_platforms KVM_PLATFORMS
make_kvm_variable kvm_os        KVM_OS

make_web_variable summarydir WEB_SUMMARYDIR
make_web_variable branch_tag WEB_BRANCH_TAG

rutdir=$(realpath ${rutdir})
summarydir=$(realpath ${summarydir})

start_time=$(NOW)

STATUS "starting at ${start_time}"

# Update the repo.
#
# Time has passed (a run finished, woke up from sleep, or the script
# was restarted) so any new commits should be fetched.
#
# Force ${branch} to be identical to ${remote} by using --ff-only - if
# it fails the script dies.

STATUS "updating repository"

git -C ${rutdir} fetch || true
git -C ${rutdir} merge --quiet --ff-only

# Update the summary web page
#
# This will add any new commits found in ${rutdir} (added by above
# fetch) and merge the results from the last test run.

STATUS "updating summary"

RUN make -C ${bindir} web-summarydir

# Select the next commit to test
#
# Search [branch_tag..HEAD] for something interesting and untested.
# If there's nothing interesting, sleep and then retry.

STATUS "looking for work"

if ! commit=$(${bindir}/gime-work.sh ${summarydir} ${rutdir} ${branch_tag}) ; then
    # Seemlingly nothing to do ...  github gets updated up every 15
    # minutes so sleep for less than that
    delay=$(expr 10 \* 60)
    now=$(date +%s)
    future=$(expr ${now} + ${delay})
    STATUS "idle; will retry at $(date -u -d @${future} +%H:%M) ($(date -u -d @${now} +%H:%M) + ${delay}s)"
    sleep ${delay}
    RESTART "after a sleep"
fi

STATUS "selected ${commit}"

# Use ${subdir} to create the results directory.
#
# Get this done ASAP so that status can start tracking it.  Once
# subdir is set, STATUS will include it.

subdir=$(make -C ${bindir} \
	      --no-print-directory \
	      print-web-variable \
	      WEB_MAKEDIR=${web_makedir} \
	      WEB_HASH=${commit} \
	      VARIABLE=WEB_SUBDIR)

resultsdir=${summarydir}/${subdir}

STATUS "creating results directory ${resultsdir}"

mkdir -p ${resultsdir}
rm -f ${summarydir}/current
ln -s ${subdir} ${summarydir}/current

# switch to the per-test logfile
#
# And make remaining logging very verbose

logfile=${resultsdir}/tester.log
echo writing log to ${logfile}
exec "$@" > ${logfile} 2>&1 </dev/null

set -vx

# populate the resultsdir

${bindir}/json-summary.sh "${start_time}" > ${resultsdir}/summary.json

RUN make -C ${bindir} web-resultsdir \
    WEB_MAKEDIR=${web_makedir} \
    WEB_HASH=${commit} \
    WEB_SUBDIR=${subdir} \
    WEB_RESULTSDIR=${resultsdir} \
    WEB_SUMMARYDIR=${summarydir}

# revert back to ${commit}
#
# Discard everything back to the commit to be tested, making that
# HEAD.  This could have side effects such as switching branches, take
# care.  If the hash is for HEAD then this is a no-op.

STATUS "checking out ${commit}"

git -C ${rutdir} reset --hard ${commit}

# Build platforms[] and platform_status[].
#
# platforms[] contains what can be built, platform_status[] indicates
# if should be built.  platform_status[] is then turned into MAKEFLAGS
# to pass down.

declare -A platforms
for platform in ${kvm_platforms} ; do
    platforms[${platform}]=${platform}
done

declare -A platform_status
for platform in ${platforms[@]} ; do
    case " ${kvm_os} " in
	*" ${platform} "* ) platform_status[${platform}]=true ;;
	* )                 platform_status[${platform}]=false ;;
    esac
done

echo "platforms=${platforms[@]}"
echo "platform_status=${platform_status[@]}"

# emit a build.json line
#
# This is merged with build.json.in to create build.json.

build_json()
{
    local run=$1
    local target=$2
    local platform=$3
    local status=$4
    jq --null-input \
       --arg run      "${run}" \
       --arg target   "${target}" \
       --arg platform "${platform}" \
       --arg status   "${status}" \
       '{ run: $run, target: $target, platform: $platform, status: $status }'
}

platform_makeflags()
{
    for platform in ${platforms[@]} ; do
	case ${platform_status[${platform}]} in
	    skip ) ;;
	    * ) echo KVM_${platform^^}=true ;;
	esac
    done
}

MAKE() {
    local target=$1 ; shift
    RUN make -C ${rutdir} ${target} \
	 $(platform_makeflags) \
	 WEB_MAKEDIR=${web_makedir} \
	 WEB_RESULTSDIR= \
	 WEB_SUMMARYDIR=
}

KVM() {
    local kvm_target=$1 ; shift
    RUN ${benchdir}/kvm ${kvm_target} \
	       $(platform_makeflags) \
	       WEB_MAKEDIR=${web_makedir} \
	       WEB_HASH=${commit} \
	       WEB_RESULTSDIR=${resultsdir} \
	       WEB_SUMMARYDIR=${summarydir}
}

run_target()
{

    local run=$1 ; shift
    local target=$1 ; shift

    local platform=
    local status=true
    local kvm_target=${target}

    if test $# -gt 0 ; then
	platform=$1 ; shift
	status=${platform_status[${platform}]}
	kvm_target=${target}-${platform}
    fi

    logfile=${resultsdir}/${kvm_target}.log
    cp /dev/null ${logfile}

    # should the target be skipped?

    if test "${status}" = skip ; then
	result=skipped
	build_json  "${run}" "${target}" "${platform}" "skipped" >> ${resultsdir}/build.json.in
	jq -s . < ${resultsdir}/build.json.in > ${resultsdir}/build.json
	return
    fi

    # Update build.json
    #
    # Merge build.json.in and the current build command into
    # build.json.

    {
	cat ${resultsdir}/build.json.in
	build_json "${run}" "${target}" "${platform}" "running"
    } | jq -s . > ${resultsdir}/build.json

    # Update the status.

    href="<a href=\"$(basename ${resultsdir})/${kvm_target}.log\">${kvm_target}</a>"
    STATUS "running '${run} ${href}'"

    # Run the target
    #
    # Notice how the first stage of the pipeline saves it's status
    # by touching ${kvm_target}.ok.

    if ${run} ${kvm_target} 2>&1 ; then
	touch ${resultsdir}/${kvm_target}.ok ;
    fi | tee -a ${resultsdir}/${kvm_target}.log

    # Figure out and save the the result.

    if test -r ${resultsdir}/${kvm_target}.ok ; then
	result=ok
    elif test ${status} != true ; then
	# for instance, OpenBSD build fail is ignored.
	result=ignored
    else
	result=failed
    fi

    # handle any magic extra processing

    case ${result}:${kvm_target} in
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

    # Maintain a list of KVM_$(OS)={true,false} flags.  These are
    # passed to to ./kvm which passes them onto MAKE controlling which
    # OS platforms are and are not enabled.

    if test -n "${platform}" ; then
	if test "${result}" != ok ; then
	    platform_status[${platform}]=skip
	fi
    fi

    gzip -v -9 ${resultsdir}/${kvm_target}.log

    # Update the status: done.

    STATUS "'${run} ${href}' ok"

    # Update build.json.
    #
    # This time add the result to build.json.in and built build.json
    # from that.

    build_json  "${run}" "${target}" "${platform}" "${result}" >> ${resultsdir}/build.json.in
    jq -s . < ${resultsdir}/build.json.in > ${resultsdir}/build.json

    if test "${result}" = failed ; then
	RESTART "${kvm_target} barfed"
    fi
}


# List of raw results; will be converted to an array

cp /dev/null ${resultsdir}/build.json.in

# Native targets

run_target MAKE distclean
run_target MAKE html

for platform in ${platforms[@]} ; do
    run_target KVM upgrade      ${platform}
    run_target KVM transmogrify ${platform}
done

run_target KVM keys

for platform in ${platforms[@]} ; do
    run_target KVM install ${platform}
done

run_target KVM check

# Eliminate any files in the repo and the latest results directory
# that are identical.
#
# Trying to do much more than this exceeds either hardlink's internal
# cache of checksums (causing hardlink opportunities to be missed); or
# the kernel's file cache (causing catatonic performance).
#
# It is assumed that git, when switching checkouts, creates new files,
# and not modifies in-place.

STATUS "hardlink $(basename ${rutdir}) $(${resultsdir})"

hardlink -v ${rutdir} ${resultsdir}

# Clean out old logs
#
# The script can run for a long time before idleing so do this every
# time.  Never delete log files for -0- commits (i.e., releases).

STATUS "deleting *.log.gz files older than 14 days"

find ${summarydir} \
     -type d -name '*-0-*' -prune \
     -o \
     -type f -name '*.log.gz' -mtime +14 -print0 | \
    xargs -0 --no-run-if-empty rm -v

RESTART "run complete"
