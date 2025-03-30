#!/bin/sh
# a config that fails during IKE_SA_INIT

set -e

set -- "$@" --ike aes

./oe.sh "$@"

RUN() {
    echo " $@"
    "$@"
}

echo : "$@" NEGOTIATION KERNEL POLICY
ipsec _kernel policy

echo : "$@" NEGOTIATION PING
case "$*" in
    *negopass* )
	../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
	;;
    *negodrop* )
	../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
	;;
esac

echo : "$@" WAIT FOR IKE_SA_INIT TO FAIL
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: ignoring IKE_SA_INIT response'
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: deleting IKE SA'

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
