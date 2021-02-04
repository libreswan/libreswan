# should fail fast
ipsec whack --impair ke-payload:0
ipsec whack --impair delete-on-retransmit
ipsec auto --up westnet-eastnet-ipv4-psk
ipsec whack --impair none
# expected to fail with a timeout
ipsec whack --impair suppress-retransmits
ipsec whack --impair revival
ipsec auto --add westnet-eastnet-ipv4-psk
ipsec auto --up westnet-eastnet-ipv4-psk
echo done
