#!/bin/sh

: ==== start ====

TESTNAME=xauth-pluto-10
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

echo done.




