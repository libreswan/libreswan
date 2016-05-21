: ==== start ====
TESTNAME=mast-pluto-02
source /testing/pluto/bin/westlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add west-east
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt

echo done

