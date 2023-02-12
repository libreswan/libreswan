ipsec auto --up road-east
ipsec whack --trafficstatus
# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.0.2.254
ipsec whack --trafficstatus
echo done
