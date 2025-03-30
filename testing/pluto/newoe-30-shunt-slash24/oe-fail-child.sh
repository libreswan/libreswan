#!/bin/sh
# a config that fails during IKE_AUTH

set -e

set -- "$@" --esp aes

./oe.sh "$@"

RUN() {
    echo " $@"
    "$@"
}

# this is racy; can't ping
echo : "$@" NEGOTIATION SHUNT
ipsec _kernel policy

echo : "$@" WAIT FOR IKE_AUTH TO FAIL
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#2: IKE_AUTH response rejected Child SA'

# doesn't happen; bug
# echo ../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: deleting IKE SA'

echo : "$@" FAILURE KERNEL POLICY
ipsec _kernel policy

echo : "$@" FAILURE SHUNTS
ipsec shuntstatus

echo : "$@" FAILURE STATES -- NONE
ipsec showstates

echo : "$@" FAILURE PING
case "$*" in
    *failpass* )
	../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
	;;
    *faildrop* )
	../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
	;;
esac
