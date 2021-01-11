# initiator sends an empty KE payload
# responder should return invalid KE
ipsec whack --impair ke-payload:empty
ipsec whack --impair delete-on-retransmit
ipsec auto --up westnet-eastnet-ipv4-psk
ipsec whack --impair none

# initiator sends valid KE
# responder sends back empty KE, should be rejected
# (responder also has re-transmits disabled)
ipsec whack --impair suppress-retransmits
ipsec auto --add westnet-eastnet-ipv4-psk
ipsec auto --up westnet-eastnet-ipv4-psk

