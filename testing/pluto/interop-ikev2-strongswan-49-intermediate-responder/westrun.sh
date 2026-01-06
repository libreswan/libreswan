../../guestbin/pluto-up-down.sh ike=aes-sha1-modp8192-ml_kem_768 -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh ike=aes-sha1-modp8192-ml_kem_768 fragmentation=no -- -I 192.0.1.254 192.0.2.254

# try with an unencrypted payload; strongSwan and libreswan disagree
# on what to feed into the mac.  See:
# https://github.com/libreswan/libreswan/issues/2510

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add intermediate
ipsec whack --impair add_unknown_v2_payload_to:IKE_INTERMEDIATE
ipsec up intermediate
