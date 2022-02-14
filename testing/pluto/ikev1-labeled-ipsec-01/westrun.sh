# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --up labeled
# there should be 1 (bogus) tunnel in each direction
ip xfrm state
ip xfrm policy
ipsec trafficstatus
# trigger acquire using the predefined ping_t context
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match '#3' -- ipsec trafficstatus
sleep 5 # allow for IKEv1 protocol sillyness
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --up     -I 192.1.2.45 192.1.2.23
# there should be 2 tunnel in each direction
ipsec trafficstatus
echo done
