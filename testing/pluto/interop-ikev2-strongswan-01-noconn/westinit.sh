: ==== start ====
TESTNAME=interop-ikev2-strongswan-01-noconn
PLUTO_EVENT_RETRANSMIT_DELAY=3
PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL=4

source /testing/pluto/bin/westnlocal.sh

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add westnet--eastnet-ikev2
ipsec auto --status
echo "initdone"
