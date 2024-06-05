ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ip.sh -s link show ipsec17
echo done
