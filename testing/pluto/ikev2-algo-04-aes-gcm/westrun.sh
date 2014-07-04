ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2-gcm-c
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo done
