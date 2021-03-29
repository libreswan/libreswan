ipsec auto --up west
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ip -s link show ipsec17
echo done
