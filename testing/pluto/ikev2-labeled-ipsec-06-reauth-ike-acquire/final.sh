# There should be 2x2 IPsec SA states (in/out for ping and ssh), all
# with same reqid.
../../guestbin/ipsec-kernel-state.sh

# And there should be one set of tunnel policies using the configured
# ipsec_spd_t label, and no outgoing %trap policy
../../guestbin/ipsec-kernel-policy.sh

# The IKE SA should be associated with the template connection
ipsec showstates
