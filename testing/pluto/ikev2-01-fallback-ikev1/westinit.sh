: ==== start ====
TESTNAME=ikev2-01-fallback-ikev1
source /testing/pluto/bin/westlocal.sh

export PLUTO_EVENT_RETRANSMIT_DELAY=3
export PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL=4

# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status
ipsec whack --debug-control --debug-controlmore --debug-parsing --debug-crypt

echo done

