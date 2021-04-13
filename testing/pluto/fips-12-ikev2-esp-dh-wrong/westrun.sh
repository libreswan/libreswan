ipsec auto --add ikev2-base
ipsec auto --up ikev2-base
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
../../guestbin/libreswan-up-down.sh ikev2-esp=aes-sha1-modp1536 -I 192.0.100.254 192.0.200.254
ipsec auto --delete ikev2-base
