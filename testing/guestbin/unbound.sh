#!/bin/bash

set -eu

verbose=${verbose-''}

PIDFILE=/var/run/unbound/unbound.pid

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
    /usr/sbin/unbound
}

function stop() {
    pid=$(cat ${PIDFILE})
    ps -p ${pid} && kill -TERM ${pid} && rm -f ${PIDFILE}
}

function reload() {
    pid=$(cat ${PIDFILE})
    kill -HUP ${pid}
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
	start
	;;
    stop )
	stop
	;;
    reload )
	reload
	;;
    restart )
	stop
	start
	;;

    *)
	err 1 "Unknown option $1"
	;;
esac
