ipsec auto --up northnet-eastnet
ping -w 4 -c 4 -I 192.0.3.254 192.0.2.254
echo done
