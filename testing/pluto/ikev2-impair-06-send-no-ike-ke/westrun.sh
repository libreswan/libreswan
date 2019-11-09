# expect quick fail
ipsec whack --impair ke-payload:omit  --impair delete-on-retransmit
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair none

# expect slower fail
ipsec whack --impair suppress-retransmits
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2

echo done
