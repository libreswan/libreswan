ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 31"
sleep 31
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 31"
sleep 20
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo done
