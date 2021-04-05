# AES: key-length required

# should work

ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 128 twice

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 0 instead of 128

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# omit the key-length attribute

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send an "empty" key-length attribute

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair emitting
ipsec whack --impair ike-key-length-attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair emitting
ipsec whack --impair child-key-length-attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# 3DES: key-length should be omitted

# should work

ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 0 instead of leaving it out

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:0
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 192 instead of leaving it out

ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:192
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

echo done
