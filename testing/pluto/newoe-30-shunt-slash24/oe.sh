#!/bin/sh

set -e

# --negopass --failnone --ike aes
what=$1 ; shift
conn=$(echo "oe $@.${what}" | sed -e 's/ --/./g' -e 's/ /-/g')

case ${what} in
    *pass* ) set -- "$@" ;;
    *fail-ike ) set -- "$@" --ike aes ;;
    *fail-child ) set -- "$@" --esp aes ;;
esac

echo :
echo :
echo : OE testing: ${conn} -- "$@"
echo :
echo :

RUN() {
    echo " $@"
    "$@"
}

echo : ${conn} RESTARTING PLUTO
RUN ipsec stop
rm OUTPUT/road.pluto.log
ln -s road.pluto.${conn}.log OUTPUT/road.pluto.log
RUN ipsec start
../../guestbin/wait-until-pluto-started

echo : ${conn} LOADING CONNECTION
RUN ipsec addconn \
    --name road \
    --retransmit-timeout 5s \
    --retransmit-interval 5s \
    --host 192.1.3.209 \
    --nexthop 192.1.3.254 \
    --authby null \
    --id %null \
    "$@" \
    --to \
    --host %opportunisticgroup \
    --authby null \
    --id %null
ipsec route road
ipsec listen

echo : ${conn} EXPECT TRAP KERNEL POLICY FOR `cat policy`
ipsec _kernel policy

echo : ${conn} TRIGGERING OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: sent IKE_SA_INIT request'
