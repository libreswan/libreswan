# There should be 2x2 IPsec SA states (in/out for ping and ssh), all
# with same reqid.
ipsec _kernel state

# And there should be one set of tunnel policies using the configured
# ipsec_spd_t label, and no outgoing %trap policy
ipsec _kernel policy

# The IKE SA should be associated with the template connection
ipsec showstates
