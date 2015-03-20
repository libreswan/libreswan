ipsec auto --up  west-east
# encrypted
ping -n -c 4 -I 192.1.2.45 192.1.2.23
# plaintext
echo "PLAINTEXT FROM WEST" | nc -p 222 -s 192.1.2.45 192.1.2.23 222
echo done
