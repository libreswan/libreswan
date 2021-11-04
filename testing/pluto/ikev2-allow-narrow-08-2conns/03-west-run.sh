
ipsec auto --up west-east-ikev2-7
echo 7 | nc -v 192.1.2.23 7

ipsec auto --up west-east-ikev2-333
echo 333 | nc -v 192.1.2.23 333
echo 7 | nc -v 192.1.2.23 7
