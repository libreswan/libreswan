#!/bin/sh

: ==== start ====

named
sleep 2

/testing/pluto/bin/look-for-key road.uml.freeswan.org AQNxbOBmD

netstat -rne

TESTNAME=oe-road-01
source /testing/pluto/bin/roadlocal.sh

#EF_PROTECT_BELOW=1 export EF_PROTECT_BELOW
#EF_PROTECT_FREE=1 export EF_PROTECT_FREE
#EF_FREE_WIPES=1 export EF_FREE_WIPES

route add -net default gw 192.1.3.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started

/testing/pluto/oe-road-01/policy-wait.sh

echo done


