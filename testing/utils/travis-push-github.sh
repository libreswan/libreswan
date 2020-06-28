#!/bin/sh

set -eu

verbose=${verbose-''}

if [ "${verbose}" = "yes" ]; then
        set -x
fi

usage() {
        printf "usage $0:\n"
	printf "\t --dir <directory> : default ${DIR}\n"
}

function info() {
    if [[ -n "${verbose}" ]]; then
        echo "# $@"
    fi
}

BRANCHES="main travis-fedora-rawhide travis-fedora-32 \
	  travis-fedora-31 travis-fedora-30 \
	  travis-fedora-29 travis-fedora-28 \
	  travis-centos-8 travis-centos-7 travis-centos-6 \
	  travis-ubuntu-focal travis-ubuntu-bionic travis-ubuntu-xenial \
	  travis-ubuntu-eon travis-ubuntu-disco travis-ubuntu-cosmic \
	  travis-debian-experimental travis-debian-sid travis-debian-bullseye \
	  travis-debian-buster travis-debian-stretch travis-debian-jessie"

DIR="${DIR:-/home/build/git/libreswan}"
FETCH_REMOTE=yes

function list_default_branches() {
	printf "${BRANCHES}\n"
}

OPTIONS=$(getopt -o hvs: --long verbose,dir:,help,list-branches,no-fetch -- "$@")

if (( $? != 0 )); then
    err 4 "Error calling getopt"
fi

eval set -- "$OPTIONS"

while true; do
	case "$1" in
		-h | --help )
			usage
			exit 0
			;;
		--list-branches )
			list_default_branches
			exit 0
			;;
		--no-fetch | --no-etch-remote )
			FETCH_REMOTE=no
			shift
			;;
		--dir )
			DIR=$2
			shift 2
			;;
		-- ) shift; break ;;

		* )
			shift
			break
			;;
	esac
done

cd ${DIR} || exit;
TIME=$(date "+%Y%m%d-%H%M")
E_START=$(date "+%s")
LOG="Push the branches to github: "
COUNTER=0
HEAD_ID_START=$(git rev-parse --short HEAD)
HEAD_ID_END=''

LOG_FILE=${LOG_FILE:-/var/tmp/github-push-error.txt}
HIST_LOG_FILE=${HIST_LOG_FILE:-/var/tmp/github-push.txt}

log_success ()
{
	HEAD_ID_END=$(git rev-parse --short HEAD)
	E_END=$(date "+%s")
    	ELAPSED=$((E_END - E_START))
	LOG="${TIME} SUCCESS ${HEAD_ID_END} pushed ${COUNTER} branches elapsed ${ELAPSED} sec"
	if [ "${HEAD_ID_END}" != "${HEAD_ID_START}" ] ; then
       		printf "${LOG}\n" >> ${HIST_LOG_FILE}
		printf "${LOG}\n" >> ${LOG_FILE}
	fi
}

clean_up ()
{
	ARG=$?
	HEAD_ID_END=$(git rev-parse --short HEAD)
    	E_END=$(date "+%s")
    	ELAPSED=$((E_END - E_START))
    	LOG="${TIME} ERROR ${HEAD_ID_START} ${HEAD_ID_END} branches ${COUNTER} ${LOG} elapsed ${ELAPSED} sec"
}

count_br()
{
	for BR in ${BRANCHES}; do
		COUNTER=$((COUNTER + 1))
	done

}

git_work()
{
(
	git checkout main
	HEAD_ID_START=`git rev-parse --short HEAD`
	if [ "${FETCH_REMOTE}" = "yes" ]; then
		git fetch origin
		git reset --hard origin/main
	fi
	HEAD_ID_END=$(git rev-parse --short HEAD)
	if [ "${HEAD_ID_END}" = "${HEAD_ID_START}" ] ; then
		echo "${TIME} IGNORE ${HEAD_ID_START} NOTHING NEW"
		return 0
	fi
	git reset --hard origin/main
	echo "${TIME} start ${HEAD_ID_START} after ${HEAD_ID_END} ${COUNTER} branches"

	for BR in ${BRANCHES}; do
		LOG="${LOG} ${BR}"
		git checkout ${BR} || git checkout -b ${BR}
		git reset --hard main
		git push --follow-tags github -f
	done

	return 0
	echo ${LOG}
) > ${LOG_FILE} 2>&1
}

trap clean_up EXIT
count_br
git_work
log_success
