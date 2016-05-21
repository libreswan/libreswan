#!/bin/sh

: ==== start ====

TESTNAME=xauth-pluto-11
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

echo done.




