# initiate a connection
../../guestbin/ping-once.sh --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match west -- ipsec trafficstatus

# let larval state expire
../../guestbin/wait-for.sh --no-match 'spi 0x00000000' -- ipsec _kernel state

ipsec _kernel policy
ipsec _kernel state

# confirm flow
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec trafficstatus

# confirm shutdown/cleanup
ipsec auto --down west
ipsec _kernel policy
ipsec _kernel state
