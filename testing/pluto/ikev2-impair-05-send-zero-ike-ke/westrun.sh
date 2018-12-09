# send KE:0

ipsec whack --impair ke-payload:0
ipsec whack --impair suppress-retransmits
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair none

# receive KE:0

ipsec whack --impair suppress-retransmits
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2

echo done
