# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --up labeled
ip xfrm state
ip xfrm pol
echo "quit" | runcon -t netutils_t nc -w 50 -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
ipsec trafficstatus
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
# let another on-demand label establish
sleep 3
# we are expecting three tunnels now (main one with 0 byte counters)
ipsec trafficstatus
echo done
