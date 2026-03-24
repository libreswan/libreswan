# don't come back
ipsec whack --impair revival
# expect quick fail
ipsec whack --impair ke_payload:omit
ipsec whack --impair timeout_on_retransmit
ipsec up westnet-eastnet-ipv4-psk-ikev2
ipsec whack --impair none
# expect slower fail
ipsec whack --impair suppress_retransmits
ipsec up westnet-eastnet-ipv4-psk-ikev2
echo done
