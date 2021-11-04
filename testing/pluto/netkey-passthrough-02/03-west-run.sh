ipsec auto --up westnet-eastnet
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
echo "PLAINTEXT FROM WEST" | nc -s 192.0.1.254 192.0.2.254 7
echo done
