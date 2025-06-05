#!/bin/sh

if=$1 ; shift
op="`uname`:$1" ; shift
ip=$1 ; shift

RUN()
{
    echo '===== cut ====='
    echo " $@"
    echo '===== tuc ====='
    "$@"
}

case "${op}" in
    Linux:add)
	RUN ip addr add "${ip}" dev "${if}"
	n=0
	while test $n -lt 10 ; do
	    if ip addr show "${if}" | grep tentative > /dev/null ; then
		:
	    else
		break
	    fi
	    n=$((n + 1))
	    sleep 1
	done
	ip addr show "${if}" | grep "${ip}"
	;;
    NetBSD:add)
	RUN ifconfig "${if}" alias "${ip}"
	ifconfig "${if}" | grep "${ip}"
	;;
    *)
	echo confused by "${op}" 1>&2
	exit 1
	;;
esac
