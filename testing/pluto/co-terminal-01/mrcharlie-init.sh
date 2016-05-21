#!/bin/sh

: ==== start ====

# nuke special route that may be there.
route delete -net 192.0.1.0 netmask 255.255.255.0 gw 192.1.2.45

named
ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add us-private-or-clear-all
ipsec auto --add private-or-clear-all
ipsec whack --listen

# verify DNS
dig -x 192.0.1.2  txt
dig -x 192.1.2.45 key
