# AES: key-length required

# send AES_128; should work

ipsec whack --impair suppress_retransmits
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES_0

ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair timeout_on_retransmit
ipsec whack --impair child_key_length_attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES_128_128; will work but probably should not

ipsec whack --impair suppress_retransmits
ipsec whack --impair ike_key_length_attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair suppress_retransmits
ipsec whack --impair child_key_length_attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES; should fail

ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair timeout_on_retransmit
ipsec whack --impair child_key_length_attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send AES_<>; should fail

ipsec whack --impair timeout_on_retransmit
ipsec whack --impair emitting
ipsec whack --impair ike_key_length_attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair timeout_on_retransmit
ipsec whack --impair emitting
ipsec whack --impair ike_key_length_attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 3DES; should work, key-length should be omitted

ipsec whack --impair suppress_retransmits
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 3DES_0; should fail (but doesn't)

ipsec whack --impair suppress_retransmits
ipsec whack --impair ike_key_length_attribute:0
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 3DES_192; should work (but doesn't)

ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:192
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

echo done
