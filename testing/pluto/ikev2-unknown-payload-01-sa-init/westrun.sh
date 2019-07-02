ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits # one packet
ipsec whack --impair add-unknown-payload-to-sa-init
: good
../bin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
: bad
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair delete-on-retransmit # one packet
ipsec whack --impair add-unknown-payload-to-sa-init
ipsec whack --impair unknown-payload-critical
../bin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
echo done
