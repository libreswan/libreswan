ipsec up west-initial
ipsec up west-additional
ipsec whack --rekey-child --name west-initial
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.20.254
ipsec whack --trafficstatus
echo done
