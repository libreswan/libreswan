# one packet, which gets eaten by XFRM, so east does not initiate
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23

# road uses PUBKEY authentication
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_AUTH request'
# east uses NULL authentication
../../guestbin/wait-for-pluto.sh --match '#1: initiator established IKE SA'
# all is good
../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA using #1'

# should show established tunnel and no bare shunts

ipsec trafficstatus
ipsec shuntstatus
ipsec _kernel state
ipsec _kernel policy

killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt

# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec trafficstatus

