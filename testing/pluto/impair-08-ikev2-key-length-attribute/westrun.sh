# AES: key-length required

# send AES_128; should work

ipsec whack --impair none
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

# send AES_0

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair ike_key_length_attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair child_key_length_attribute:0
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

# send AES_128_128; will work but probably should not

ipsec whack --impair none
ipsec whack --impair ike_key_length_attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

ipsec whack --impair none
ipsec whack --impair child_key_length_attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

# send AES; should fail

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair ike_key_length_attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair child_key_length_attribute:omit
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

# send AES_<>; should fail

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair emitting
ipsec whack --impair ike_key_length_attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair emitting
ipsec whack --impair ike_key_length_attribute:empty
../../guestbin/libreswan-up-down.sh aes128 -I 192.0.1.254 192.0.2.254

# send 3DES; should work, key-length should be omitted

ipsec whack --impair none
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254

# send 3DES_0; should fail (but doesn't)

ipsec whack --impair none
ipsec whack --impair ike_key_length_attribute:0
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254

# send 3DES_192; should work (but doesn't)

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair ike_key_length_attribute:192
../../guestbin/libreswan-up-down.sh 3des -I 192.0.1.254 192.0.2.254

echo done
