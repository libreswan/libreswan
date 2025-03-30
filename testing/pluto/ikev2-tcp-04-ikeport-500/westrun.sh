ipsec up west

../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus

# should show tcp being used
ipsec _kernel state
ipsec _kernel policy
