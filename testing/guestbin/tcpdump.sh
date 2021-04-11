#!/bin/sh
set -eu
verbose=${verbose-''}

if [ "${verbose}" = "yes" ]; then
        set -x
fi

interface="eth1"
sync_wait_stop=5
sync_wait_start=1
sync_wai=${sync_wait_start}
this_host=$(hostname)
host=${this_host}

function usage () {
    cat <<EOF >/dev/stderr

Usage:

    $0 --start -i <ethX> [--host <hostname>]
    $0 --stop [--host <hostname>]

Start tcpdump with host test specific name and pid /tmp/

Stop and read tcpdump output to the console

EOF
}

if test $# -lt 1; then
	usage
	exit 1
fi

OPTIONS=$(getopt -o h,i: --long verbose,help,testname:,host:,start,stop -- "$@")
if (( $? != 0 )); then
    err 4 "Error calling getopt"
fi

eval set -- "$OPTIONS"

while true; do
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
		--start )
			action="start"
			shift
			;;
		--stop )
			action="stop"
			shift
			;;
		* )
			shift
			break
			;;
	esac
done

function set_file_names()
{
	tmp_dir=/tmp
	testname=$(basename ${PWD})
	out_file="${host}.${testname}.pcap"
	out_path="${tmp_dir}/${out_file}"
	pid_path="${tmp_dir}/${host}.${testname}.pid"
}

function start_tcpudmp()
{
	set_file_names
	# call stop if there are any previous runawy tcpdump
	sync_wait=${sync_wait_start}
	stop_tcpudmp
	rm -fr ${out_path}
	rm -fr ${pid_path}
	tcpdump -s 0 -i ${interface} -w ${out_path} 2>/dev/null > /dev/null & echo $! > ${pid_path}
}

function stop_tcpudmp()
{
	set_file_names
	pid=$(cat ${pid_path} 2>/dev/null) || true
	kill -TERM -p ${pid} 2>/dev/null > /dev/null || true
	# for tcpudump output to write and sync
	sleep ${sync_wait}; sync;
	rm -fr ${pid_path}
}

if [ "${host}" != "${this_host}" ]; then
	exit 0
fi

if [ "${action}" = "start" ]; then
	start_tcpudmp
elif [ "${action}" = "stop" ]; then
	sync_wait=${sync_wait_stop}
	stop_tcpudmp
	cp ${out_path} OUTPUT/
	tcpdump -n -r OUTPUT/${out_file} not arp and not ip6 and not stp
fi
