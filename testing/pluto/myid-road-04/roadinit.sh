#!/bin/sh
# NOTE: this is shared by a number of tests
: ==== start ====
hostname road.uml.freeswan.org

ifconfig eth0 inet 192.1.3.213
route delete -net default
route add -net default gw 192.1.3.254

netstat -rne

named
sleep 2
/testing/pluto/bin/look-for-txt 213.3.1.192.in-addr.arpa. AQNxbOBmD

TESTNAME=myid-road-04
source /testing/pluto/bin/roadlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/oe-road-01/policy-wait.sh

echo done


