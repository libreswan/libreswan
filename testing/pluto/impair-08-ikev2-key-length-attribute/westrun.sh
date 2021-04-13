# AES: key-length required

# send AES_128; should work

ipsec whack --impair suppress-retransmits
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES_0

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES_128_128; will work but probably should not

ipsec whack --impair suppress-retransmits
ipsec whack --impair ike-key-length-attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair suppress-retransmits
ipsec whack --impair child-key-length-attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES; should fail

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES_<>; should fail

ipsec whack --impair delete-on-retransmit
ipsec whack --impair emitting
ipsec whack --impair ike-key-length-attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair delete-on-retransmit
ipsec whack --impair emitting
ipsec whack --impair ike-key-length-attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 3DES; should work, key-length should be omitted

ipsec whack --impair suppress-retransmits
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 3DES_0; should fail

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:0
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 3DES_192; should work?

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:192
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

echo done
