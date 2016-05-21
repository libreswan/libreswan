#!/bin/sh

: ==== start ====

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/basic-pluto-01/eroutewait.sh trap
ipsec auto --delete packetdefault

iptables -t nat -A POSTROUTING -s 192.0.1.0/24 -d 0.0.0.0/0 -j SNAT --to-source 192.1.2.45

ipsec eroute --eraf inet --add --src 0.0.0.0/0 --dst 0.0.0.0/0 --said %pass

route add -host 1.2.3.4 gw 192.1.2.254 dev ipsec0
