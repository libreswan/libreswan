# one packet, which gets eaten by XFRM, so east does not initiate
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23

# wait on OE IKE negotiation; should show established tunnel and no bare shunts
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec _kernel state
ipsec _kernel policy
iptables -t nat -L -n
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
# 1 ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done
