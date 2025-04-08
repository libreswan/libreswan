#!/bin/sh

set -e

conn=oe$(echo "$@" | sed -e 's/--/./g' -e 's/ /-/g')
args="$@"

echo :
echo :
echo : OE testing: ${args} ${conn}
echo :
echo :

RUN() {
    echo " $@"
    "$@"
}

echo : ${args} RESTARTING PLUTO
ipsec stop
rm OUTPUT/road.pluto.log
ln -s road.pluto.${conn}.log OUTPUT/road.pluto.log
ipsec start
../../guestbin/wait-until-pluto-started

echo : ${args} LOADING CONNECTION
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

echo : ${args} TRAPPING `cat policy`
ipsec _kernel policy

echo : ${args} TRIGGERING OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: sent IKE_SA_INIT request'
