ipsec auto --start northnet-eastnets
ipsec auto --status | grep northnet-eastnets
../../guestbin/ping-once.sh --up -I 198.18.66.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 198.18.66.254 192.0.22.254
ipsec whack --trafficstatus
echo done
