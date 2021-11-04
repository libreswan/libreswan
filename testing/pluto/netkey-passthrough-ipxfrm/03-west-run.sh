ipsec auto --up west-east
# encrypted
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# plaintext
echo "PLAINTEXT FROM WEST" | nc -p 7 -s 192.1.2.45 192.1.2.23 7
echo done
