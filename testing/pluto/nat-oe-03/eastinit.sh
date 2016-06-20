#!/bin/sh

TESTNAME=nat-oe-03
source /testing/pluto/bin/eastlocal.sh

# set up proxy ARP for road's "internal" address
echo 1 >/proc/sys/net/ipv4/conf/eth0/proxy_arp

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--eastnet-nat

arp -an

echo done


