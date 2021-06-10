# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --route labeled
ip xfrm state
ip xfrm pol
echo "quit" | runcon -t netutils_t nc  -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
# there should be 1 tunnel
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# one IPsec SA and a %trap policy from the template conn
ip xfrm state
ip xfrm pol
echo done
