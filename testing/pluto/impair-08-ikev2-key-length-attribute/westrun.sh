# AES: key-length required

# should work

ipsec whack --impair suppress-retransmits
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 0 instead of 128

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:duplicate
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:duplicate
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 0 instead of 128

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:0
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:0
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# omit the key-length attribute

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:omit
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair delete-on-retransmit
ipsec whack --impair child-key-length-attribute:omit
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send an "empty" key-length attribute

ipsec whack --impair delete-on-retransmit
ipsec whack --impair emitting
ipsec whack --impair ike-key-length-attribute:empty
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair delete-on-retransmit
ipsec whack --impair emitting
ipsec whack --impair ike-key-length-attribute:empty
../../pluto/bin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# 3DES: key-length should be omitted

# should work

ipsec whack --impair suppress-retransmits
../../pluto/bin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 0 instead of leaving it out

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:0
../../pluto/bin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 192 instead of leaving it out

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ike-key-length-attribute:192
../../pluto/bin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

echo done
