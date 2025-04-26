ipsec whack --impair revival

# UDP will fail
ipsec up west
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# TCP will succeed
ipsec whack --impair trigger_revival:1
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# should show tcp being used
ipsec _kernel state
ipsec _kernel policy
