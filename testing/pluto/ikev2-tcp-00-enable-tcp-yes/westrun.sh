ipsec whack --impair revival

# TCP will establish!
ipsec up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# should show TCP state and policy
ipsec _kernel state
ipsec _kernel policy
