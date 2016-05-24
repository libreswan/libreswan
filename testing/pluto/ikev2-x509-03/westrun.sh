ipsec auto --up ikev2-westnet-eastnet-x509-cr
ping -n -c4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo "done"
