ipsec whack --impair revival

ipsec up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
ipsec showstates | grep separate-transports

ipsec _kernel state
ipsec _kernel policy
