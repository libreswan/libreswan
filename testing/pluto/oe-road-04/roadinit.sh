#!/bin/sh

: ==== start ====

ifconfig eth0 inet 192.1.3.212
route delete -net default
route add -net default gw 192.1.3.254

netstat -rne

named
sleep 2
/testing/pluto/bin/look-for-key roadkey.uml.freeswan.org AQNxbOBmD

mkdir -p /tmp/oe-road-04
cp /testing/pluto/oe-road-04/road.conf  /tmp/oe-road-04/ipsec.conf
cp /etc/ipsec.secrets                   /tmp/oe-road-04

mkdir -p /tmp/oe-road-04/ipsec.d/policies
cp /etc/ipsec.d/policies/* /tmp/oe-road-04/ipsec.d/policies
: make sure that target is in policy private!
echo 192.0.2.2/32	>>/tmp/oe-road-04/ipsec.d/policies/private

IPSEC_CONFS=/tmp/oe-road-04 export IPSEC_CONFS

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/oe-road-01/policy-wait.sh

echo done


