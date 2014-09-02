ipsec auto --up  west-east
ping -n -c 4 -I 192.1.2.45 192.1.2.23
echo "PLAINTEXT FROM WEST" | nc -s 192.1.2.45 192.1.2.23 222
echo done
