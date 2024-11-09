ipsec auto --up west-east
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
echo "PLAINTEXT FROM WEST" | socat - TCP:192.1.2.23:7,bind=192.1.2.45,sourceport=7
echo done
