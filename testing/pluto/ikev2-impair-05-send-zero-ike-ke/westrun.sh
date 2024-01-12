# send KE:0 (which is invalid)
# expect KE:0 in response
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair ke_payload:0
ipsec whack --impair suppress_retransmits
# DH should fail
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2

# send valid KE
# expect KE:0 in response (which is invalid)
ipsec whack --impair none
ipsec whack --impair revival
ipsec whack --impair suppress_retransmits
# DH should fail
ipsec auto --up westnet-eastnet-ipv4-psk-ikev2

echo done
