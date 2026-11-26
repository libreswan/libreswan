ipsec whack --impair revival

# should fail fast
ipsec whack --impair ke_payload:empty
ipsec up westnet-eastnet-ipv4-psk-ikev2

# expected to fail with a timeout
ipsec whack --impair ke_payload:no
ipsec up westnet-eastnet-ipv4-psk-ikev2

echo done
