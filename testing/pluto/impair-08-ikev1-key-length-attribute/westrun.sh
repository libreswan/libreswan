# should work
ipsec whack --impair suppress-retransmits
../../pluto/bin/libreswan-up-down.sh ike=aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# force a quick death

# AES: key-length required

# send 0 instead of 128
ipsec whack --impair delete-on-retransmit
ipsec whack --impair key-length-attribute:0
../../pluto/bin/libreswan-up-down.sh ike=aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# omit the key-length attribute
ipsec whack --impair delete-on-retransmit
ipsec whack --impair key-length-attribute:omit
../../pluto/bin/libreswan-up-down.sh ike=aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# 3DES: key-length should be omitted

# send 0 instead of leaving it out
ipsec whack --impair delete-on-retransmit
ipsec whack --impair key-length-attribute:0
../../pluto/bin/libreswan-up-down.sh ike=3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 192 instead of leaving it out
ipsec whack --impair delete-on-retransmit
ipsec whack --impair key-length-attribute:192
../../pluto/bin/libreswan-up-down.sh ike=3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

echo done
