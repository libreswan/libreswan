../../guestbin/ping-once.sh --down -I 192.1.3.208 192.1.2.23
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
sleep 5
# should show tunnels and no shunts
ipsec whack --trafficstatus
ipsec whack --shuntstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.208 192.1.2.23
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
echo done
