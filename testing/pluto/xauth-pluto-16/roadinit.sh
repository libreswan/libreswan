#!/bin/sh

: ==== start ====

TESTNAME=`basename $PWD`
export TESTNAME

/testing/guestbin/swan-prep --hostname road --x509
netstat -rn

ipsec setup stop
pidof pluto >/dev/null && killall pluto 2> /dev/null
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager stop
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf 

/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add modecfg-road-east

echo done
