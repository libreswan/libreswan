# normal case, not sent
ipsec whack --impair v2-proposal-integ:no
../../guestbin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
# force its addition
ipsec whack --impair v2-proposal-integ:allow-none
../../guestbin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
# force its exclusion
ipsec whack --impair v2-proposal-integ:drop-none
../../guestbin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
ipsec whack --impair v2-proposal-integ:no

# normal case, not sent
ipsec whack --impair v2-proposal-dh:no
../../guestbin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
# force its addition
ipsec whack --impair v2-proposal-dh:allow-none
../../guestbin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
# force its exclusion
ipsec whack --impair v2-proposal-dh:drop-none
../../guestbin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
ipsec whack --impair v2-proposal-integ:no
