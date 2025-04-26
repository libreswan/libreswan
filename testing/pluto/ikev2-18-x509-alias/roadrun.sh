ipsec auto --up road-east-ipv4-psk-ikev2
ipsec auto --up road-east-ipv6-psk-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/ping-once.sh --up -I 192.0.11.254 192.0.2.254
../../guestbin/ping-once.sh --up 2001:db8:1:2::23
ipsec whack --trafficstatus
echo done
