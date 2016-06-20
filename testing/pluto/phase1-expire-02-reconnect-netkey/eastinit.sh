: ==== start ====
TESTNAME=phase1-expire-02-reconnect-netkey
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-crypt
