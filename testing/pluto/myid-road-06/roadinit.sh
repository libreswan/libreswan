#!/bin/sh

: this is an non-existant name
hostname nonexist.uml.freeswan.org.

ifconfig eth0 inet 192.1.3.209
route delete -net default
route add -net default gw 192.1.3.254

netstat -rne

named
sleep 2
(echo "txt 12334 nonexist.uml.freeswan.org."; echo quit) | ipsec lwdnsq -X
(echo "key 12334 nonexist.uml.freeswan.org."; echo quit) | ipsec lwdnsq -X

: script will also put 192.0.2.2 into private food group
TESTNAME=myid-road-05
source /testing/pluto/bin/roadlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/oe-road-01/policy-wait.sh

ipsec whack --status | grep 192.0.2.2

echo done


