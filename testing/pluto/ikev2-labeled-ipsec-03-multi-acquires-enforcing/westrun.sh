# for port re-use in tests with protoport selectors
echo 1 >/proc/sys/net/ipv4/tcp_tw_reuse
ipsec auto --up labeled
# expect policy but no states
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

# trigger an acquire; both ends initiate Child SA
echo "quit" | runcon -t netutils_t nc -w 50 -p 4301 -vvv 192.1.2.23 4300 2>&1 | sed "s/received in .*$/received .../"
../../guestbin/wait-for.sh --match 'labeled..2.' ipsec trafficstatus
# no shunts; two transports; two x two states
ipsec shuntstatus
ipsec showstates
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

# let another on-demand label establish
ping -n -q -c 4 -I 192.1.2.45 192.0.2.254
../../guestbin/wait-for.sh --match 'labeled..4.' ipsec trafficstatus
# there should be no shunts
ipsec shuntstatus
ipsec showstates
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh

echo done
