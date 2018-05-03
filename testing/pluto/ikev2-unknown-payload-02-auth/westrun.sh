ipsec whack --impair none
ipsec whack --impair suppress-retransmits # one packet
ipsec whack --impair add-unknown-payload-to-auth
: good
../bin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
: bad
ipsec whack --impair none
ipsec whack --impair delete-on-retransmit
ipsec whack --impair add-unknown-payload-to-auth,unknown-payload-critical
../bin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
echo done
