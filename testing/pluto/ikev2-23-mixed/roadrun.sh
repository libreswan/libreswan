ipsec auto --up road-east-ipv4
ipsec auto --up road-east-ipv4-ikev2
ping -n -c 2 -I 192.0.1.254 192.0.2.254
echo done
