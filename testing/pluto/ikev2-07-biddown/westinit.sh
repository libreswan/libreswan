: ==== start ====
TESTNAME=ikev2-07-biddown
source /testing/pluto/bin/westlocal.sh

export PLUTO_EVENT_RETRANSMIT_DELAY=3
export PLUTO_MAXIMUM_RETRANSMISSIONS_INITIAL=4

# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP

# drop a bunch of IKE packets
iptables -F OUTPUT
iptables -A OUTPUT -o eth1 -p udp --dport 500 -m recent --rcheck --hitcount 6 -j ACCEPT
iptables -A OUTPUT -o eth1 -p udp --dport 500 -m recent --set -j DROP

ipsec setup start
/testing/pluto/bin/wait-until-pluto-started

ipsec whack --whackrecord /var/tmp/ikev2.record
ipsec auto --add westnet-eastnet-ipv4
ipsec auto --status
ipsec whack --debug-control --debug-controlmore

echo "initdone"

