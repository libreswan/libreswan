# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
# route; should be two policies
ipsec auto --route labeled
../../guestbin/ipsec-look.sh
# trigger traffic
echo "quit" | runcon -t netutils_t timeout 15 nc  -p 4301 -vvv 192.0.2.254 4300 2>&1 | sed "s/received in .*$/received .../"
# there should be 2 tunnels - both inactive in one direction
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ip xfrm state
echo done
