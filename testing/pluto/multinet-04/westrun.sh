ipsec auto --up  westnets-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ping -n -c 4 -I 192.0.11.254 192.0.2.254
ipsec whack --trafficstatus
echo done
