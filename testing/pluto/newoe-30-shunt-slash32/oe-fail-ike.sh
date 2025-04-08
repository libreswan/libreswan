#!/bin/sh
# a config that fails during IKE_SA_INIT

. ./oe.sh fail-ike "$@"

RUN() {
    echo " $@"
    "$@"
}

echo : ${conn} EXPECT NEGOTIATION KERNEL POLICY
ipsec _kernel policy

echo : ${conn} TRY NEGOTIATION PING
case "$*" in
    *negopass* )
	../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
	;;
    *negodrop* )
	../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
	;;
esac

echo : ${conn} WAIT FOR IKE_SA_INIT TO FAIL
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: ignoring IKE_SA_INIT response'
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: deleting IKE SA'

echo : ${conn} WAIT FOR ACQUIRE TO EXPIRE
../../guestbin/wait-for.sh --timeout 10 --no-match 'spi 0x00000000' -- ipsec _kernel state

echo : ${conn} FAILURE KERNEL POLICY - WHEN failpass OR faildrop
ipsec _kernel policy

echo : ${conn} FAILURE SHUNT - WHEN failpass OR faildrop
ipsec shuntstatus

echo : ${conn} EXPECT NO FAILURE STATES
ipsec showstates

echo : ${conn} TRY FAILURE PING
case "$*" in
    *failpass* )
	../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
	;;
    *faildrop* )
	../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
	;;
esac

echo : ${conn} WAIT FOR FAILURE SHUNT TO EXPIRE
../../guestbin/wait-for.sh --no-match % -- ipsec shuntstatus

echo : ${args} EXPECT TRAP KERNEL POLICY FOR `cat policy`
ipsec _kernel policy
