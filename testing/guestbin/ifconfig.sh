#!/bin/sh

if=$1 ; shift
op=$1 ; shift
ip=$1 ; shift

case $op in
    add)
	ip addr add ${ip} dev ${if}
	n=0
	while test $n -lt 10 ; do
	    if ip addr show ${if} | grep tentative > /dev/null ; then
		:
	    else
		break
	    fi
	    n=$((n + 1))
	    sleep 1
	done
	ip addr show ${if} | grep ${ip}
	;;
esac
