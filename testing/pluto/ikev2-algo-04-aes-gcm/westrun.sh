ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2-gcm-c
ping -n -c 2 192.0.2.254
ipsec look
echo done
