ipsec auto --up west
../../guestbin/ping-once.sh --up -I 2001:db8:0:1::254 2001:db8:0:2::254
ipsec whack --trafficstatus
echo done
