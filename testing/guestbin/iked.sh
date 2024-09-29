#!/bin/sh

if test $# -ne 1 ; then
    echo "usage: $0 {start,stop}" 1>&2
    exit 1
fi

case $1 in
    start )
	/sbin/iked -dv > /tmp/iked.log 2>&1 & sleep 1
	echo $! > /tmp/iked.pid
	;;
    stop )
	kill `cat /tmp/iked.pid`
	;;
    * )
	echo "unrecongized: $1" 1>&2
	exit 1
	;;
esac
