#!/bin/sh

: ==== start ====
# NOTE: this is shared by a number of tests

named
dig road.uml.freeswan.org. key

ping -n -c 4 192.0.2.2

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/oe-road-01/policy-wait.sh

ipsec auto --add private-or-clear
ipsec auto --add us-private-or-clear
ipsec auto --add us-private-or-clear-all

# now, re-read the policy groups
ipsec whack --listen

ipsec auto --route private-or-clear
ipsec auto --route us-private-or-clear
ipsec auto --route us-private-or-clear-all

echo done

ipsec eroute

ipsec whack --debug-dns --debug-control --debug-oppo --debug-controlmore

