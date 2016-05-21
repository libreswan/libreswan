#!/bin/sh

: ==== start ====

TESTNAME=x509-pluto-06
source /testing/pluto/bin/eastlocal.sh

iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

arp -s 192.0.2.1 10:00:00:dc:bc:01

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north-east-x509-pluto-02

echo done


