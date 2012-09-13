#!/bin/sh
: ==== start ====
TESTNAME=psk-pluto-03
ipsec setup stop
umount /usr/local; mount /usr/local

hostname road.uml.freeswan.org

ifconfig eth0 inet 192.1.3.174
route delete -net default 
route add -net default gw 192.1.3.254

# netstat -rn

ls -al /testing/pluto/bin/roadlocal.sh
source /testing/pluto/bin/roadlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--eastnet-psk
echo done
