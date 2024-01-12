# should fail fast
ipsec whack --impair ke_payload:0
ipsec whack --impair timeout_on_retransmit
ipsec auto --up westnet-eastnet-ipv4-psk
ipsec whack --impair none
# expected to fail with a timeout
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec auto --add westnet-eastnet-ipv4-psk
ipsec auto --up westnet-eastnet-ipv4-psk
echo done
