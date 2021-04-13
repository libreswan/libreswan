ipsec auto --up westnet-eastnet-ikev2
ping -n -q -c 4 -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
# fails
#ipsec auto --up  westnet-eastnet-ikev2-ipv6
echo done
