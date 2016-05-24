ipsec auto --up  westnet-eastnet-ikev2
# ideally trafficstatus would show IPsec SA like eroute did
ipsec whack --trafficstatus
echo done
