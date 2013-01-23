#!/bin/sh

: ==== start ====
export TESTNAME=xauth-pluto-12

/testing/guestbin/swan-prep --testname $TESTNAME 
ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add modecfg-road--eastnet-psk

echo done.




