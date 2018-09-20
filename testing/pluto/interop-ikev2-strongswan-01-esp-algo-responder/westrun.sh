../bin/libreswan-up-down.sh esp=null-md5 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh esp=null-sha1 -I 192.0.1.254 192.0.2.254
../bin/libreswan-up-down.sh esp=null_auth_aes_gmac-null -I 192.0.1.254 192.0.2.254
modinfo chacha20poly1305 > /dev/null && ../bin/libreswan-up-down.sh esp=chacha20_poly1305-null -I 192.0.1.254 192.0.2.254 || true

echo done
