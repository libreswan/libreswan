#!/bin/sh
set -eu
# sanitize and and sort "ip -o addr" output
#
# this is necessary due to ifindex changes between kvm and namespace
# this is a wrapper to sort and sanitize "ip addr show scope global" + scope 50
# ip -o addr | sed 's/^[0-9][0-9]*:\ //;s/\\//;s/\ \ */ /g' | grep -v "scope link" |  sed 's/scope.*//'
verbose=${verbose-''}

if [ "${verbose}" = "yes" ]; then
        set -x
fi

OPTIONS=$(getopt -o h --long verbose,help -- "$@")
if (( $? != 0 )); then
    err 4 "Error calling getopt"
fi

eval set -- "$OPTIONS"

usage() {
        echo "$0"
        echo "$0 <dev name>"
	echo "'ip -o addr show' output sanitized and sorted"
}

while true; do
	case "$1" in
		-h | --help )
			usage
			exit 0
			shift
			;;
		* )
			shift
			break
			;;
	esac
done

ifface=${1:-''}
if [ -n "${ifface}" ] ; then
	ifface="show dev ${ifface}"
fi

# dump raw version of what ../bin/ip-addr-show.sh manages
echo ==== cut ====
ip addr ${ifface}
echo ==== tuc ====

ip -o addr ${ifface} | {
		sed 's/^[0-9][0-9]*:\ //;s/\\//;s/\ \ */ /g;/scope\ \(local\|host\|link\)/d'
	} | {
		sed 's/scope.*//;s/brd .*//'
	} | {
		sort
	} | {
		# extra white space at the end
		sed 's/ $//'
	}
