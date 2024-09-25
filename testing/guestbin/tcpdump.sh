#!/bin/sh

set -eu
verbose=${verbose-''}

if [ "${verbose}" = "yes" ]; then
        set -x
fi

interface="eth1"
sync_wait_stop=5
sync_wait_start=1
this_host=$(hostname)
host=${this_host}
ip6="not ip6"

 usage() {
    cat <<EOF >/dev/stderr

Usage:

    $0 --start -i <ethX> [--host <hostname>]
    $0 --stop [--host <hostname>] [--ip6]
    $0 --kill [--host <hostname>]

Start tcpdump saving output to /tmp/

Stop tcpdump and dump captured output to the console

Kill tcpdump

Specify --host to only run on <hostname>.

EOF
}

if test $# -lt 1; then
	usage
	exit 1
fi

action=

while test $# -gt 0; do
	case "$1" in
		-h | --help )
                        usage
                        exit 0
                        shift
                        ;;
		--host )
			host=$2
			shift 2
			;;
		-i )
			interface=$2
			shift 2
			;;
		-ip6 )
			ip6=''
			shift
			;;

		--start )
			action="start"
			shift
			;;
		--stop )
			action="stop"
			shift
			;;
		--kill )
			action="kill"
			shift
			;;

		* )
			echo "unrecognized option: $1" 1>&2
			exit 1
			;;
	esac
done

set_file_names()
{
	tmp_dir=/tmp
	testname=$(basename ${PWD})
	out_path="${tmp_dir}/${host}.${testname}.${interface}.tcpdump.pcap"
	log_path="${tmp_dir}/${host}.${testname}.${interface}.tcpdump.log"
	pid_path="${tmp_dir}/${host}.${testname}.${interface}.tcpdump.pid"
}

start_tcpdump()
{
	# call stop if there are any previous runawy tcpdump - don't show output
	stop_tcpdump >/dev/null 2>&1
	rm -f ${out_path}
	rm -f ${log_path}
	rm -f ${pid_path}
	tcpdump -s 0 -i ${interface} -w ${out_path} > ${log_path} 2>&1 &
	echo $! > ${pid_path}
	sleep ${sync_wait_start}
	echo tcpdump started
}

stop_tcpdump()
{
    if test -r ${pid_path} ; then
	pid=$(cat ${pid_path})
	(kill -TERM ${pid} 2> /dev/null > /dev/null)

	if [ -f ${out_path} ]; then
	    # wait for tcpudump output to write and sync
	    sleep 1
	    while kill -0 ${pid} > /dev/null 2>&1 ; do
		sleep 1
	    done
	    cp ${out_path} OUTPUT/
	    cp ${log_path} OUTPUT/
	    rm -f ${pid_path}
	fi
    else
	echo tcpdump ${pid_path} is not running
    fi
}

if [ "${host}" != "${this_host}" ]; then
	exit 0
fi

set_file_names

case "${action}" in
    start)
	start_tcpdump
	;;
    stop)
	stop_tcpdump
	tcpdump -n -r ${out_path} not arp and ${ip6} and not stp
	;;
    kill)
	stop_tcpdump
	;;
esac
