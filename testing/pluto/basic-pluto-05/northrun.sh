ipsec auto --up northnet-eastnet-nonat
ping -n -c 4 -I 192.0.3.254 192.0.2.254
echo done
