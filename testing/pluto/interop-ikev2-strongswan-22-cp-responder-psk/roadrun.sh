ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
route -n
ping -n -c 2 -I 192.0.2.1 192.0.2.254
echo done
