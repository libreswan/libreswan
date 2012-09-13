#!/bin/sh

: ==== start ====

TESTNAME=aggr-pluto-03
source /testing/pluto/bin/northlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north-east-aggr-pluto-03
echo done
