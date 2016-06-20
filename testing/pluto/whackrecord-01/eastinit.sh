: ==== start ====
TESTNAME=whackrecord-01
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/east.record
ipsec auto --add westnet-eastnet
ipsec whack --debug-control --debug-controlmore --debug-crypt

