: ==== start ====
TESTNAME=ike-des128-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup restart
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet
grep 'TPM enabled' /tmp/pluto.log
ipsec whack --debug-control --debug-controlmore --debug-crypt
