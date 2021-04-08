ipsec auto --up westnet-eastnet-ikev2
ping -n -q -c 2 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
