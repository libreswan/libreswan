#!/bin/sh

: ==== start ====

TESTNAME=x509-fail-12
source /testing/pluto/bin/eastlocal.sh

#rm /tmp/$TESTNAME/ipsec.d/crls/cacrlnotyetvalid.pem
rm /tmp/$TESTNAME/ipsec.d/crls/cacrlvalid.pem
rm /tmp/$TESTNAME/ipsec.d/crls/cacrlexpired.pem

iptables -A INPUT -i eth1 -s 192.0.3.0/24 -d 0.0.0.0/0 -j DROP

arp -s 192.0.2.1 10:00:00:dc:bc:01

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north-east-x509-fail-12

echo done


