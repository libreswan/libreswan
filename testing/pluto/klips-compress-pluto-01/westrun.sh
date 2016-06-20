ipsec auto --up  westnet-eastnet-compress
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec eroute
ipsec auto --down westnet-eastnet-compress
echo done
