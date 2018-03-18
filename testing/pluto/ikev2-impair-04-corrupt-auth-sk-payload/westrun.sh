ipsec whack --impair suppress-retransmits # one packet
ipsec whack --impair replay-encrypted,corrupt-encrypted
../bin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
echo done
