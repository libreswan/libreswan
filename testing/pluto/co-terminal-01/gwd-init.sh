#!/bin/sh
: ==== start ====

# move gateway to the virtual 4 network so that we can get OE to work.
route delete default
ifconfig eth1 inet 192.1.4.45 netmask 255.255.255.0 broadcast 192.1.4.255
route add -net default gw 192.1.4.254

named

dig 2.2.0.192.in-addr.arpa. txt

# nuke special route that may be there.
route delete -net 192.0.2.0 netmask 255.255.255.0 gw 192.1.2.23

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add us-private-or-clear-all
ipsec auto --add let-my-dns-go
ipsec auto --add us-let-my-dns-go
ipsec whack --listen
ipsec auto --route us-private-or-clear-all
ipsec auto --route let-my-dns-go
ipsec auto --route us-let-my-dns-go

ipsec eroute


