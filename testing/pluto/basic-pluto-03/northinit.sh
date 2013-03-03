#!/bin/sh
: ==== start ====
ipsec setup stop
pidof pluto >/dev/null && killall pluto 2> /dev/null
rm -f /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager stop
ping -c 4 -n 192.0.3.254
/usr/local/libexec/ipsec/_stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet--eastnet-nat
ipsec auto --status
echo "initdone"
