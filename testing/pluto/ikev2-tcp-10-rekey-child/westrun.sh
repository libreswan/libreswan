ipsec up  west

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

ipsec _kernel state
ipsec _kernel policy

ipsec whack --rekey-child --name west

# rekey of IPsec SA means traffic counters should go back to 0
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

ipsec _kernel state
ipsec _kernel policy
