ipsec auto --up westnets-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.11.254 192.0.2.254
ipsec whack --trafficstatus
echo done
