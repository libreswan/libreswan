#!/bin/sh
# an config that connects

set -e

args="$@"
./oe.sh "$@"

RUN() {
    echo " $@"
    "$@"
}

echo : ${args} ESTABLISH
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#2: initiator established Child SA'
../../guestbin/wait-for.sh --timeout 10 --match '#2' -- ipsec trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
../../guestbin/ipsec-kernel-policy.sh
ipsec trafficstatus
ipsec shuntstatus

echo : ${args} SHUTDOWN
ipsec down road
echo : ${args} NO STATES
ipsec showstates
echo : ${args} NO SHUNTS
ipsec shuntstatus
echo : ${args} TRAP POLICY
../../guestbin/ipsec-kernel-policy.sh
