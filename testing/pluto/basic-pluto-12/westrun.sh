ipsec auto --up  westnet-eastnet
echo encrypted-with-ipsec | nc -s 192.0.1.254 192.0.2.254 22
echo plaintext | nc -s 192.0.1.254 192.0.2.254 222
echo done
