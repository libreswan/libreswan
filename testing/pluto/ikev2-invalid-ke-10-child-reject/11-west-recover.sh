ipsec up west-additional
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.20.254
ipsec whack --trafficstatus
echo done
