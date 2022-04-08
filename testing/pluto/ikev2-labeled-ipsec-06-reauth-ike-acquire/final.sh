# There should be FOUR IPsec SA states (two sets), all with same
# reqid. And there should be one set of tunnel policies using the
# configured ipsec_spd_t label, and no outgoing %trap policy
../../guestbin/ipsec-look.sh
# The IKE SA should be associated with the template connection
ipsec showstates
