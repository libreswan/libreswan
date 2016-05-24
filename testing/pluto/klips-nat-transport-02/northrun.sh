ipsec auto --route north-east-pass
ipsec auto --up  north-east-port3
echo test | nc 192.1.2.23 2
echo test | nc 192.1.2.23 3
echo done
