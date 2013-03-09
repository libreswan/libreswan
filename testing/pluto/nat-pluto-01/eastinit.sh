#!/bin/sh
: ==== start ====

/testing/guestbin/swan-prep --x509 

certutil -d /etc/ipsec.d -D north -n north
certutil -L -d /etc/ipsec.d

# this tests non-esp marker with fragments using libreswan. Next test
# uses racoon
#iptables -I INPUT -p udp -m length --length 0x5dc:0xffff -j LOGDROP

ipsec setup stop
/usr/local/libexec/ipsec/_stackmanager stop
rm -fr /var/run/pluto/pluto.pid
/usr/local/libexec/ipsec/_stackmanager start
/usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add northnet--eastnet-nat

echo done.

