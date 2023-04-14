# initiate a connection
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match west -- ipsec trafficstatus

# let larval state expire
../../guestbin/wait-for.sh --no-match 'spi 0x00000000' -- ../../guestbin/ipsec-kernel-state.sh

../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh

# confirm flow
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec trafficstatus

# confirm shutdown/cleanup
ipsec auto --down west
../../guestbin/ipsec-kernel-policy.sh
../../guestbin/ipsec-kernel-state.sh
