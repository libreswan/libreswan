#!/bin/sh

# make sure that NAT is working
#ping -c 4 -n sunrise

TESTNAME=nat-oe-03
source /testing/pluto/bin/roadlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add road--eastnet-nat

echo done
