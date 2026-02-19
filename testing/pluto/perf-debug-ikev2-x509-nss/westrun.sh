ipsec auto --up ikev2-westnet-eastnet-x509-cr
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --down ikev2-westnet-eastnet-x509-cr
ipsec auto --up ikev2-westnet-eastnet-x509-cr
ipsec auto --down ikev2-westnet-eastnet-x509-cr
ipsec auto --up ikev2-westnet-eastnet-x509-cr
ipsec auto --down ikev2-westnet-eastnet-x509-cr
ipsec auto --up ikev2-westnet-eastnet-x509-cr
ipsec auto --down ikev2-westnet-eastnet-x509-cr
ipsec auto --up ikev2-westnet-eastnet-x509-cr
ipsec auto --down ikev2-westnet-eastnet-x509-cr
ipsec auto --up ikev2-westnet-eastnet-x509-cr
ipsec auto --down ikev2-westnet-eastnet-x509-cr
echo "done"
