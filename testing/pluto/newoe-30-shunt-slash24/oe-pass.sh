#!/bin/sh
# an config that connects

set -e

args="$@"
./oe.sh "$@"

RUN() {
    echo :
    echo : OE ${args}
    echo " $@"
    "$@"
}

# should establish; and packets flow
RUN ../../guestbin/wait-for.sh --timeout 10 --match '#2' -- ipsec trafficstatus
RUN ../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
RUN ../../guestbin/ipsec-kernel-policy.sh
RUN ipsec trafficstatus
RUN ipsec shuntstatus
