ipsec whack --impair suppress_retransmits # one packet
ipsec whack --impair replay_encrypted
ipsec whack --impair corrupt_encrypted
../../guestbin/libreswan-up-down.sh westnet-eastnet-ipv4-psk-ikev2 -I 192.0.1.254 192.0.2.254
echo done
