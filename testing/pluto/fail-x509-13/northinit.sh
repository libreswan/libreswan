#!/bin/sh

: ==== start ====

TESTNAME=x509-fail-13

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north-east-x509-fail-13
echo done
