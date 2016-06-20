: ==== start ====
TESTNAME=interop-ikev2-racoon-01-noconn
source /testing/pluto/bin/westnlocal.sh

export PLUTO_EVENT_RETRANSMIT_DELAY=3
export PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL=4

ipsec start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add westnet--eastnet-ikev2
ipsec auto --status
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt
echo "initdone"
