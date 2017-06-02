: default algorithms
../bin/libreswan-up-down.sh ikev2-defaults -I 192.0.1.254 192.0.2.254
: other combinations
../bin/libreswan-up-down.sh ikev2-ike=aes128-sha1 -I 192.0.1.254 192.0.2.254
echo done
