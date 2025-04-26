ipsec whack --impair revival

# UDP will fail

ipsec up west
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# TCP will still fail

ipsec whack --impair trigger_revival:1
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec trafficstatus

# expect nothing
ipsec _kernel state
ipsec _kernel policy
