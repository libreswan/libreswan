#!/bin/sh

# make sure that NAT is working
#ping -c 4 -n sunrise

TESTNAME=nat-pluto-02
source /testing/pluto/bin/roadlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road--eastnet-nat

echo done
