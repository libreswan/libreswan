#!/bin/sh
set -eu

verbose=${verbose-''}
NSD_EXTRA_OPTS=${NSD_EXTRA_OPTS-''}

PIDFile=/run/nsd/nsd.pid

if [ "${verbose}" = "yes" ]; then
        set -x
fi

function err() {
        local exitcode=$1
        shift
        echo "ERROR: $@" >&2
        exit $exitcode
}
usage() {
        echo "usage\n"
}

function info() {
    if [[ -n "${verbose}" ]]; then
        echo "# $@"
    fi
}

function start() {
	# next lines are combination nsd-keygen.service and nsd.service
	/usr/sbin/nsd-control-setup -d /etc/nsd/
	# fork and run in the background
	/usr/sbin/nsd -c /etc/nsd/nsd.conf $NSD_EXTRA_OPTS
}

function stop() {
	[ -f ${PIDFile} ] && \
		(ps -p $(cat ${PIDFile}) && kill -TERM $(cat ${PIDFile}) && \
		rm ${PIDFile}) || true
}

function restart() {
	stop
	start
}

function reload() {
	ps -p $(cat ${PIDFile}) && kill -HUP $(cat ${PIDFile})
}

OPTIONS=$(getopt -o hgvs: --long verbose,start,stop,restart,reload,help -- "$@")
if (( $? != 0 )); then
    err 4 "Error calling getopt"
fi

eval set -- "$OPTIONS"

while true; do
        case "$1" in
                -h | --help )
                        usage
                        shift
                        exit 0
			;;
		*)
			shift
			break
			;;
	esac
done

case "$1" in

	start )
		start $@
		shift
		;;
	stop )
		stop $@
		shift
		;;
	reload )
		reload $@
		shift
		;;

	restart )
		restart $@
		shift
		;;

	*)
		err 1 "Unknown option $1"
		shift
		break
		;;
esac

