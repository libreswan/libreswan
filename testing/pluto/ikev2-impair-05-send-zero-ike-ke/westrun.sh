# send KE:0
ipsec whack --impair ke-payload:0
ipsec whack --impair suppress-retransmits
# should fail
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair none
# receive KE:0
ipsec whack --impair suppress-retransmits
# using --add to reset whack fd, otherwise console output lost :/
ipsec auto --add  westnet-eastnet-ipv4-psk-ikev2
# should fail
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
echo done
