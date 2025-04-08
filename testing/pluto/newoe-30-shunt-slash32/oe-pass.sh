#!/bin/sh
# an config that connects

. ./oe.sh pass "$@"

RUN() {
    echo " $@"
    "$@"
}

echo : ${conn} ESTABLISH
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#2: initiator established Child SA'
../../guestbin/wait-for.sh --timeout 10 --match '#2' -- ipsec trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23

echo : ${conn} EXPECT IPSEC POLICY
ipsec _kernel policy
echo : ${conn} EXPECT ONE PACKET
ipsec trafficstatus
echo : ${conn} EXPECT NO SHUNTS
ipsec shuntstatus

echo : ${conn} SHUTDOWN
ipsec down road

echo : ${conn} EXPECT NO STATES
ipsec showstates
echo : ${conn} EXPECT NO SHUNTS
ipsec shuntstatus
echo : ${conn} EXPECT TRAP POLICY
ipsec _kernel policy
