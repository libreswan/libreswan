#!/bin/sh

set -e

args="$@"

RUN() {
    echo :
    echo : OE ${args}
    echo " $@"
    "$@"
}

conn=oe$(echo "$@" | sed -e 's/--/./g' -e 's/ /-/g')

echo :
echo : ${conn}
echo :
RUN ipsec stop

# save this run in its own log file
RUN rm OUTPUT/road.pluto.log
RUN ln -s road.pluto.${conn}.log OUTPUT/road.pluto.log

# start
RUN ipsec start
RUN ../../guestbin/wait-until-pluto-started

RUN ipsec whack --name road \
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

RUN ipsec route road
RUN ipsec listen

# default
RUN ../../guestbin/ipsec-kernel-policy.sh

# trigger OE; expect things to initiate
RUN ../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
RUN ../../guestbin/wait-for-pluto.sh --timeout 10 --match '#1: sent IKE_SA_INIT request'
