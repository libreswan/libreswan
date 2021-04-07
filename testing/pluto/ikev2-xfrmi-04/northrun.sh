ipsec auto --up northnet-eastnet
ping -n -w 4 -c 2 -I 192.0.3.254 192.0.22.254
echo done
