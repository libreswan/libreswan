ipsec auto --up eastnet-westnet-ikev2
ipsecctl -v -v -k -s all
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsecctl -v -v -k -s all
ipsec trafficstatus

echo done
