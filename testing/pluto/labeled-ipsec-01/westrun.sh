# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --up labeled
echo test | nc -p 4301 -vvv 192.0.1.254 4300
echo done
