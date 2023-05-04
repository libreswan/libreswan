# should fail fast
ipsec whack --impair revival
ipsec whack --impair ke-payload:empty
ipsec whack --impair timeout-on-retransmit
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair none

# expected to fail with a timeout
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2

echo done
