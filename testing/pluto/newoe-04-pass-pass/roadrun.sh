# trigger OE; expect private-or-clear to have no traffic
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private-or-clear -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up   -I 192.1.3.209 192.1.2.23
# trigger the shunt for 7.*
ipsec whack --shuntstatus
../../guestbin/ping-once.sh --down -I 192.1.3.209 7.7.7.7
../../guestbin/wait-for.sh --match 7.7.7.7 -- ipsec whack --shuntstatus
../../guestbin/ping-once.sh --up   -I 192.1.3.209 7.7.7.7
# wait on OE retransmits and rekeying
sleep 5
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# 7.7.7.7 is %pass, we should be able to ping it
../../guestbin/ping-once.sh --up -I 192.1.3.209 7.7.7.7
ipsec _kernel state
ipsec _kernel policy
# letting acquire and shunt exire
sleep 60
ipsec _kernel state
ipsec _kernel policy
sleep 60
ipsec _kernel state
ipsec _kernel policy
sleep 60
ipsec _kernel state
ipsec _kernel policy
killall ip > /dev/null 2> /dev/null
cp /tmp/xfrm-monitor.out OUTPUT/road.xfrm-monitor.txt
echo done
