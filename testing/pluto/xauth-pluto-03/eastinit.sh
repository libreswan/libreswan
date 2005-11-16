#!/bin/sh

TESTNAME=xauth-pluto-03
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-policy-loaded

echo done.




