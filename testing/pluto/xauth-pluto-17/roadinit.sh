#!/bin/sh
ifconfig eth0 inet 192.1.3.194
route delete -net default 
route add -net default gw 192.1.3.254
ip ro li
#
/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add xauth-road--eastnet-psk
ipsec auto --status
echo "initdone"
