# send KE:0 -- which is invalid

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair ke-payload:0
ipsec whack --impair suppress-retransmits
# should fail with syntax-error response
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2

# receive KE:0 -- which is invalid

ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
# should fail fail with syntax error
ipsec auto --up  westnet-eastnet-ipv4-psk-ikev2

echo done
