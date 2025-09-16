ipsec auto --up ikev2-westnet-eastnet-x509-cr
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec whack --trafficstatus
echo "done"
