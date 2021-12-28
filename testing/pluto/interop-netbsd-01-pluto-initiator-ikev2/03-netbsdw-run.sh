../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
ipsec auto --add eastnet-westnet-ikev2
ipsec auto --start eastnet-westnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
