#!/bin/sh

: ==== start ====

named

dig 2.2.0.192.in-addr.arpa. txt
dig japan.uml.freeswan.org. key

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add me-private-or-clear
ipsec auto --add let-my-dns-go
ipsec whack --listen
ipsec auto --route me-private-or-clear
ipsec auto --route let-my-dns-go

ipsec eroute

