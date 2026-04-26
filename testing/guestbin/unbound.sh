#!/bin/sh
set -eu

verbose=${verbose-''}
UNBOUND_OPTIONS=${UNBOUND_OPTIONS-''}

PIDFile=/run/unbound/unbound.pid

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
        echo "usage $0\n"
}

function info() {
    if [[ -n "${verbose}" ]]; then
        echo "# $@"
    fi
}

function start() {
	# fork and run in the background
	/usr/sbin/unbound $UNBOUND_OPTIONS
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

