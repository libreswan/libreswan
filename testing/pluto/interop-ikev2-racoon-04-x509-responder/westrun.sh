ipsec auto --up  west-east-ikev2
ipsec look
ping -n -c1 -I 192.0.2.254 192.0.1.254
echo done
