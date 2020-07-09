# send AES_128; should work

ipsec whack --impair suppress-retransmits
../../pluto/bin/libreswan-up-down.sh conf -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add IKE transform type 6 id 0 unknown

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ikev2-add-ike-transform:0x60000
../../pluto/bin/libreswan-up-down.sh conf -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add IKE transform type 3 (PRF) id 0xff unknown

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ikev2-add-ike-transform:0x3ffff
../../pluto/bin/libreswan-up-down.sh conf -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add CHILD transform type 6 id 0 unknown

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ikev2-add-child-transform:0x60000
../../pluto/bin/libreswan-up-down.sh conf -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add CHILD transform type 3 (PRF) id 0xffff unknown

ipsec whack --impair delete-on-retransmit
ipsec whack --impair ikev2-add-child-transform:0x3ffff
../../pluto/bin/libreswan-up-down.sh conf -I 192.0.1.254 192.0.2.254
ipsec whack --impair none
