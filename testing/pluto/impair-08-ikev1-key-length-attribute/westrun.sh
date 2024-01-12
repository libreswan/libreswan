# AES: key-length required

# should work

ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
../../guestbin/libreswan-up-down.sh aes128 --alive -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 128 twice

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 --down -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair child_key_length_attribute:duplicate
../../guestbin/libreswan-up-down.sh aes128 --down -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 0 instead of 128

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:0
../../guestbin/libreswan-up-down.sh aes128 --down -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair child_key_length_attribute:0
../../guestbin/libreswan-up-down.sh aes128 --down -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# omit the key-length attribute

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:omit
../../guestbin/libreswan-up-down.sh aes128 --alive -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair child_key_length_attribute:omit
../../guestbin/libreswan-up-down.sh aes128 --down -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send an "empty" key-length attribute

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair emitting
ipsec whack --impair ike_key_length_attribute:empty
../../guestbin/libreswan-up-down.sh aes128 --alive -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair emitting
ipsec whack --impair child_key_length_attribute:empty
../../guestbin/libreswan-up-down.sh aes128 --down -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

#
# 3DES: key-length should be omitted
#

# should work

ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
../../guestbin/libreswan-up-down.sh 3des --alive -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 0 instead of leaving it out

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:0
../../guestbin/libreswan-up-down.sh 3des --down -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

# send 192 instead of leaving it out

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec whack --impair ike_key_length_attribute:192
../../guestbin/libreswan-up-down.sh 3des --alive -I 192.0.1.254 192.0.2.254
ipsec whack --impair none

echo done
