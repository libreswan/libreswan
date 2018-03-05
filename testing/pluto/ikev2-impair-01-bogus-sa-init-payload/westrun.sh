ipsec whack --impair none
ipsec whack --impair send-no-retransmits # one packet
ipsec whack --impair add-bogus-payload-to-sa-init
: good
../bin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
: bad
ipsec whack --impair none
ipsec whack --impair delete-on-retransmit
ipsec whack --impair add-bogus-payload-to-sa-init,bogus-payload-critical
../bin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
echo done
