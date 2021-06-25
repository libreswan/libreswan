# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --up labeled
# expect policy but no states
../../guestbin/ipsec-look.sh
# trigger an acquire
echo "quit" | runcon -t netutils_t nc -w 50 -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
# wait for it to establish and flow
../../guestbin/wait-for.sh --match 'labeled..1.' ipsec trafficstatus
# there should be no shunts
ipsec shuntstatus
# let another on-demand label establish
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for.sh --match 'labeled..2.' ipsec trafficstatus
# there should be no shunts
ipsec shuntstatus
ipsec showstates
echo done
