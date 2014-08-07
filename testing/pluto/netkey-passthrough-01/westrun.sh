ipsec auto --up  west-east
ping -n -c 4 -I 192.1.2.45 192.1.2.23
echo "test" | nc -s 192.1.2.45 192.1.2.23 22
echo done
