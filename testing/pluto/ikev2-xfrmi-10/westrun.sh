ipsec up west # sanitize-retransmits
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ip.sh -s link show ipsec17
../../guestbin/ip.sh -d link show ipsec17
ipsec delete west # sanitize-retransmits
../../guestbin/ip.sh -d link show ipsec17
../../guestbin/ip.sh address show dev ipsec17
echo done
