ipsec auto --up rad-eastnet-fqdn-ikev2
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
