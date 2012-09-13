: ==== start ====
TESTNAME=nss-leftrsasigkey2-01
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-ipv4-rsa2
ipsec whack --debug-control --debug-controlmore --debug-crypt
