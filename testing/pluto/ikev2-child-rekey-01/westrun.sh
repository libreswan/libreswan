ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "sleep 30"
sleep 30
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
sleep 20
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo done
