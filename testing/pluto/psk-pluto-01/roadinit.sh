#!/bin/sh
: ==== start ==== 
TESTNAME=psk-pluto-01
hostname road.uml.freeswan.org
/testing/guestbin/swan-prep --testname $TESTNAME 
ipsec setup stop
pidof pluto >/dev/null && killall pluto 2> /dev/null
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager stop
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--eastnet-psk

ipsec auto --status
sleep 2
echo "initdone"
