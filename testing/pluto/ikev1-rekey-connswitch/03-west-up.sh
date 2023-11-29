ipsec auto --up TUNNEL-A
ipsec auto --up TUNNEL-B
ipsec auto --up TUNNEL-C
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.244
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.234
#IKE sa will be on TUNNEL-A
ipsec auto --status | grep ISAKMP
