# On EAST, block inbound messages, specifically the IKE SA rekey
# request that is about to be sent.

ipsec whack --impair block_inbound

# back to WEST
