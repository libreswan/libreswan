ipsec auto --up  westnet-eastnet-aes256
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done
