#!/bin/sh

named
inetd
dig road.uml.freeswan.org. key

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add private-or-clear
ipsec auto --add us-private-or-clear
ipsec auto --add us-private-or-clear-all

: wait for packetdefault to show up
/testing/pluto/basic-pluto-01/eroutewait.sh trap

ipsec auto --route private-or-clear
ipsec auto --route us-private-or-clear
ipsec auto --route us-private-or-clear-all

# now, re-read the policy groups
ipsec whack --listen

/testing/pluto/policy-01/policy-wait.sh 4

nc -w 5 192.1.2.23 4

echo done

ipsec eroute

