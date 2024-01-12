ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_initiator_spi:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
