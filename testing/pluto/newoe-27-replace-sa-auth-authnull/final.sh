# only east should show 1 tunnel
ipsec whack --trafficstatus
# east shows the authnull is matched on preferred non-null connection,
# then cannot find a (non-authnull) match and rejects it. So an
# additional 'authenticated' partial state lingers
ipsec status | grep STATE_
