# there should be one tunnel, but there can be two. If two,
# their reqid cannot be the same.
ipsec trafficstatus
../../guestbin/ipsec-kernel-state.sh
ip xfrm policy
# test packet flow
../../guestbin/ip.sh address add 192.0.1.254/24 dev eth0
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# did it split over two IPsec SA's or not? just curious
ipsec trafficstatus
# stop ipsec for a bit, then restart. see what happens
ipsec stop
sleep 10
ipsec start
sleep 3
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
