# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --up labeled
ip xfrm state
ip xfrm pol
echo "quit" | runcon -t netutils_t nc -w 50 -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
sleep 3
ipsec trafficstatus
# there should be no shunts
ipsec shuntstatus
# let another on-demand label establish
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
sleep 3
ipsec trafficstatus
# there should be no shunts
ipsec shuntstatus
echo done
