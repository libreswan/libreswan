#!/bin/sh
/testing/guestbin/swan-prep
ping -c 4 -n 192.0.3.254
ipsec _stackmanager start 
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet--eastnet-nonat
ipsec auto --status
echo "initdone"
