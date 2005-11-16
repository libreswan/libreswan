#!/bin/sh

TESTNAME=nat-pluto-03

hostname road.uml.freeswan.org

ifconfig eth0 inet 192.1.3.194
route delete -net default 
route add -net default gw 192.1.3.254

netstat -rn

source /testing/pluto/bin/roadlocal.sh

ipsec setup start

echo done


