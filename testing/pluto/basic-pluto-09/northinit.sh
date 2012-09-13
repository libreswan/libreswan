#!/bin/sh

# make sure that NAT is working
#ping -c 4 -n sunrise
: ==== start ====
TESTNAME=basic-pluto-09
source /testing/pluto/bin/northlocal.sh

ping -q -c 8 -n 192.1.2.23

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add northnet--eastnet-nat

echo done
