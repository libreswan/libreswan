# there should be one tunnel, but there can be two. If two,
# their reqid cannot be the same.
ipsec trafficstatus
ip xfrm state
ip xfrm pol
# test packet flow
ip addr add 192.0.1.254/24 dev eth0
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# did it split over two IPsec SA's or not? just curious
ipsec trafficstatus
# delete one of the two identical conns
ipsec whack --deletestate 1
ipsec trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
