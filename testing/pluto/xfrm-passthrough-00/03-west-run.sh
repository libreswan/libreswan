ipsec auto --up west-east
# encrypted
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# plaintext
echo "PLAINTEXT FROM WEST" | socat - TCP:192.1.2.23:7,bind=192.1.2.45,sourceport=7
echo done
