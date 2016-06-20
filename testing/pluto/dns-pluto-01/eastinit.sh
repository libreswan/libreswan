: ==== start ====
TESTNAME=dns-pluto-01
source /testing/pluto/bin/eastlocal.sh

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add dns--westnet-eastnet
ipsec whack --debug-dns
