#!/bin/sh

: ==== start ====

ifconfig eth0 inet 192.1.3.210
route delete -net default 
route add -net default gw 192.1.3.254

netstat -rne

named
sleep 2

/testing/pluto/bin/look-for-txt roadtxt.uml.freeswan.org AQNxbOBmD

TESTNAME=oe-road-02
source /testing/pluto/bin/roadlocal.sh
ipsec setup start

/testing/pluto/oe-road-01/policy-wait.sh

echo done


