
ipsec auto --up west-east-ikev2-222
echo 222 | nc -v 192.1.2.23 222

ipsec auto --up west-east-ikev2-333
echo 333 | nc -v 192.1.2.23 333
echo 222 | nc -v 192.1.2.23 222
