# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --up labeled
ip xfrm state
ip xfrm pol
echo "quit" | nc -p 4301 -vvv 192.1.2.23 4300
ipsec trafficstatus
echo done
