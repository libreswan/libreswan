: ==== start ====
TESTNAME=dns-pluto-01
source /testing/pluto/bin/westlocal.sh

: all occurs without DNS
ipsec setup stop
ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec auto --add dns--westnet-eastnet
ipsec whack --debug-dns
ipsec whack --status

echo done

