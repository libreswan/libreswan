#!/bin/sh
: ==== start ====
TESTNAME=netkey-psk-pluto-06
hostname road.uml.freeswan.org

/testing/guestbin/swan-prep --testname $TESTNAME
ipsec setup stop
pidof pluto >/dev/null && killall pluto 2> /dev/null
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager stop
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--eastnet-psk

ipsec auto --status
sleep 2
echo "initdone"
