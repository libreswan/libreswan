# There should be FOUR IPsec SA states (two sets), all with same
# reqid. And there should be one set of tunnel policies using the
# configured ipsec_spd_t label, and no outgoing %trap policy
ipsec _kernel state
ipsec _kernel policy
# The IKE SA should be associated with the template connection
ipsec showstates
