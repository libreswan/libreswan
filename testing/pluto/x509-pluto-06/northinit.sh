#!/bin/sh

: ==== start ====

#TESTNAME=x509-pluto-06
#
#source /testing/pluto/bin/northlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north-east-x509-pluto-02
echo done
