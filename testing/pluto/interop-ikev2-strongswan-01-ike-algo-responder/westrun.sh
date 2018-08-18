ipsec whack --impair suppress-retransmits --debug crypt,crypt-low

../bin/libreswan-up-down.sh ike=chacha20poly1305-sha2-dh19 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ike=aes128-sha2-dh19 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ike=aes128-sha2-dh20 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ike=aes128-sha2-dh21 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ike=aes128-sha1-dh19 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ike=aes128-sha1-dh20 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh ike=aes128-sha1-dh21 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ike=aes_ctr128-sha1-dh21 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ike=3des-sha2-modp2048 -I 192.0.1.254 192.0.2.254

../bin/libreswan-up-down.sh ike=aes128-aes_xcbc-modp2048 -I 192.0.1.254 192.0.2.254

echo done
