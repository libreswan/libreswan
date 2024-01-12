# should fail fast
ipsec whack --impair revival
ipsec whack --impair ke_payload:empty
ipsec whack --impair timeout_on_retransmit
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair none

# expected to fail with a timeout
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2

echo done
