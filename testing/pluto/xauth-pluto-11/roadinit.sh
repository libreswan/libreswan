#!/bin/sh

: ==== start ====

hostname road

ifconfig eth0 inet 192.1.3.194
route delete -net default
route add -net default gw 192.1.3.254

netstat -rn

TESTNAME=xauth-pluto-11
source /testing/pluto/bin/roadlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --replace xauth-road--eastnet
ipsec whack --status | grep xauth-road--eastnet

ipsec whack --debug-control --debug-controlmore

echo done


