# send AES_128; should work

ipsec whack --impair suppress_retransmits
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add IKE transform type 0xee (aka ROOF) id 0 unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_ike_transform:0xee0000
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add IKE transform type 0x03 (PRF) id 0xffff unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_ike_transform:0x03ffff
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add CHILD transform type 0xee (aka ROOF) id 0 unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_child_transform:0xee0000
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add CHILD transform type 0x03 (PRF) id 0xffff unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_child_transform:0x03ffff
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none
