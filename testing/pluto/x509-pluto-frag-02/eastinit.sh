#!/bin/sh

: ==== start ====
TESTNAME=`basename $PWD`
export TESTNAME

/testing/guestbin/swan-prep --testname $TESTNAME  --hostname east --x509 

certutil -d /etc/ipsec.d -D road -n road
certutil -L -d /etc/ipsec.d

#iptables -I OUTPUT -f -j LOGDROP # drop UDP fragments
iptables -I INPUT -p udp -m length --length 0x5dc:0xffff -j LOGDROP

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add x509

echo done.
