# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --route labeled
ip xfrm state
ip xfrm pol
echo "quit" | runcon -t netutils_t timeout 15 nc  -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
# there should be 2 tunnels - both inactive in one direction
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
sleep 4
# There should be FOUR IPsec SA states (two sets), all with same reqid
ip xfrm state
# There should be one set of tunnel policies using the configured ipsec_spd_t label, plus an outgoing %trap policy
ip xfrm pol
echo done
