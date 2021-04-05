ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-initiator-spi:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
