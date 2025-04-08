# initiate a connection
../../guestbin/ping-once.sh --forget -I 192.0.3.254 192.0.2.254
../../guestbin/wait-for.sh --match north -- ipsec trafficstatus

# let larval state expire
../../guestbin/wait-for.sh --no-match 'spi 0x00000000' -- ipsec _kernel state

ipsec _kernel policy
ipsec _kernel state

# confirm flow
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
ipsec trafficstatus

# confirm shutdown/cleanup
ipsec auto --down north
ipsec _kernel policy
ipsec _kernel state
