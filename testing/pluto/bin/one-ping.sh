#!/bin/sh

# Send a single ping packet (-c 1) then wait one second (-w 1) for a
# reply.
#
# To avoid a race between the default one second ping interval and the
# explicit one second wait time (sometimes two packets would be sent),
# the ping interval is made greater than the wait time (-i 2).

if test $# -eq 0; then
    echo "Usage: $0 [-I <interface>] <destination>" 1>&2
    exit 1
fi

if ping -q -i 2 -w 1 -n -c 1 "$@" > /dev/null ; then
    echo up
    exit 0
else
    echo down
    exit 1
fi
