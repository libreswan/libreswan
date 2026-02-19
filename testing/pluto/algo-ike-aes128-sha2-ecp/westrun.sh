../../guestbin/pluto-up-down.sh keyexchange=ikev1 ike=aes128-sha2-ecp256 -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh keyexchange=ikev1 ike=aes128-sha2-ecp384 -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh keyexchange=ikev1 ike=aes128-sha2-ecp521 -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh keyexchange=ikev1 ike=aes128-sha2-ecp521 pfs=yes -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh keyexchange=ikev1 ike=aes128-sha2-ecp521 pfs=yes esp=aes128-sha2-ecp256 -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh keyexchange=ikev2 ike=aes128-sha2-ecp256 -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh keyexchange=ikev2 ike=aes128-sha2-ecp384 -- -I 192.0.1.254 192.0.2.254
../../guestbin/pluto-up-down.sh keyexchange=ikev2 ike=aes128-sha2-ecp521 -- -I 192.0.1.254 192.0.2.254
