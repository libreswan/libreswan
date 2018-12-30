#!/bin/sh

timeout=30

if test $# -eq 0; then
    cat <<EOF 1>&2

Usage: $0 [--timeout N] <pattern>

Repeatedly grep the output of:

	   whack --trafficstatus

until it matches <pattern> or until the approximate timeout (default
${timeout}) expires.

EOF
    exit 1
fi


if test "$1" = "--timeout"; then
    shift ; timeout=$1 ; shift
fi

count=0
while true ; do
    if ipsec whack --trafficstatus | grep "$@" ; then
	exit 0
    fi
    count=$(expr ${count} + 1)
    if test ${count} -ge ${timeout} ; then
	echo timeout after ${timeout} seconds
	exit 1
    fi
    sleep 1
done
