# send AES_128; should work

ipsec whack --impair suppress_retransmits
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add IKE transform type 6 id 0 unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_ike_transform:0x60000
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add IKE transform type 3 (PRF) id 0xff unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_ike_transform:0x3ffff
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add CHILD transform type 6 id 0 unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_child_transform:0x60000
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# add CHILD transform type 3 (PRF) id 0xffff unknown

ipsec whack --impair suppress_retransmits
ipsec whack --impair ikev2_add_child_transform:0x3ffff
../../guestbin/libreswan-up-down.sh conf --up -I 192.0.1.254 192.0.2.254
ipsec whack --impair none
