#!/bin/sh

: ==== start ====

TESTNAME=x509-fail-02

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add north-east-x509-fail-02
echo done
