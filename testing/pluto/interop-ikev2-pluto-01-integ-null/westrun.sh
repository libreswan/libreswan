ipsec whack --debug-all
../bin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
ipsec whack --debug-all --impair ikev2-include-integ-none
../bin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
ipsec whack --debug-all --impair ikev2-exclude-integ-none
../bin/libreswan-up-down.sh ike,esp=aes_gcm  -I 192.0.1.254 192.0.2.254
