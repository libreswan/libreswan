#!/bin/sh
: ==== start ====
hostname roadtxt.uml.freeswan.org

ifconfig eth0 inet 192.1.3.209
route delete -net default
route add -net default gw 192.1.3.254

netstat -rne

named
sleep 2
/testing/pluto/bin/look-for-txt roadtxt.uml.freeswan.org AQNxbOBmD

TESTNAME=myid-road-02
source /testing/pluto/bin/roadlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/oe-road-01/policy-wait.sh

echo done


