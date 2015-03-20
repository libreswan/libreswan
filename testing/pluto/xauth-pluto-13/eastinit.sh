#!/bin/sh

: ==== start ====
TESTNAME=`basename $PWD`
export TESTNAME

/testing/guestbin/swan-prep --testname $TESTNAME  --hostname east --x509 
ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add modecfg-road-east

echo done.
