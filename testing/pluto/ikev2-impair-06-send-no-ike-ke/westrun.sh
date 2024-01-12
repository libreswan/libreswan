# expect quick fail
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair ke_payload:omit
ipsec whack --impair timeout_on_retransmit
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2

# expect slower fail
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2

echo done
