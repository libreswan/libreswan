#!/bin/sh

# Send a single ping packet (-c 1) then wait one second (-w 2) for a
# reply.
#
# To avoid a race between the default one second ping interval and the
# one second wait time that sometimes results in two ping packets
# being sent, the ping interval is made greater than the wait time (-i
# 2).

if ping -q -i 2 -w 1 -n -c 1 "$@" > /dev/null ; then
    echo up
    exit 0
else
    echo down
    exit 1
fi
