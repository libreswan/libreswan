: ==== start ====

TESTNAME=dpd-06
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west-east

ipsec whack --debug-lifecycle --debug-control --debug-dpd


