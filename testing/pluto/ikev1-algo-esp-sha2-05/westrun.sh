ipsec auto --up  westnet-eastnet-ipv4-psk-ikev1
ping -n -c 2 -I 192.0.1.254 192.0.2.254
echo done
