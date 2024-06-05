ipsec auto --up west
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ip -s link show ipsec17
ip -d link show ipsec17
ipsec auto --delete west
ip -d link show ipsec17
../../guestbin/ip.sh address show dev ipsec17
echo done
