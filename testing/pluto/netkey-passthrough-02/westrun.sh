ipsec auto --up  westnet-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
echo "PLAINTEXT FROM WEST" | nc -s 192.0.1.254 192.0.2.254 222
echo done
