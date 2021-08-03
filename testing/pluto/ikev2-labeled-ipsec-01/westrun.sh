# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
# route; should be two policies
ipsec auto --route labeled
../../guestbin/ipsec-look.sh
# trigger traffic using the predefined ping_t context
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec trafficstatus
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --up     -I 192.1.2.45 192.1.2.23
# there should be 2 tunnels - both inactive in one direction
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ip xfrm state
echo done
