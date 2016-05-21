#!/bin/sh

named
sleep 2
dig road.uml.freeswan.org. key
(echo "key 12334 road.uml.freeswan.org"; echo quit) | ipsec lwdnsq -X

netstat -rne

route add -net default gw 192.1.3.254

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/policy-01/policy-wait.sh 5

echo done


