# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
# route; should be two policies
ipsec auto --route labeled
ipsec _kernel state
ipsec _kernel policy
# trigger traffic
echo "quit" | runcon -t netutils_t timeout 15 nc  -p 4301 -vv 192.0.2.254 4300 2>&1 | sed -e 's/received in .*$/received .../' -e 's/Version .*/Version .../'
# there should be 2 tunnels - both inactive in one direction
ipsec trafficstatus | sed -e 's/=[1-9][0-9]*,/=<NNN>,/g'
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state
echo done
