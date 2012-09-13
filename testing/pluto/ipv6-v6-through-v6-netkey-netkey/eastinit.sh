: ==== start ====
TESTNAME=ipv6-v6-through-v6-netkey-netkey
source /testing/pluto/bin/eastlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add westnet-eastnet-6in6
ipsec whack --debug-control --debug-controlmore --debug-crypt
