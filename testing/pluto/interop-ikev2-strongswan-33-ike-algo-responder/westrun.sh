ipsec whack --impair suppress-retransmits --debug crypt,crypt-low

../bin/libreswan-up-down.sh ikev2-ike=aes128-md5-dh19 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ikev2-ike=aes128-md5-dh20 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ikev2-ike=aes128-md5-dh21 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ikev2-ike=aes128-sha1-dh19 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ikev2-ike=aes128-sha1-dh20 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ikev2-ike=aes128-sha1-dh21 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ikev2-ike=aes_ctr128-sha1-dh21 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ikev2-ike=3des-md5-modp2048 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ikev2-ike=aes128-aes_xcbc-modp2048 -I 192.0.1.254 192.0.2.254

echo done
