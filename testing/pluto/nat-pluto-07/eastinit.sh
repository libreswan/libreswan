#!/bin/sh

: ==== start ====

TESTNAME=nat-pluto-07
source /testing/pluto/bin/eastlocal.sh

arp -s 192.0.2.1 10:00:00:dc:bc:01
route delete -net default 
route add -net default gw 192.1.2.1

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add northnet--eastnet-nat

echo done


