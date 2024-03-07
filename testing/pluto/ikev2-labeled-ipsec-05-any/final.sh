: sync console - east has output from _getpeercon_server waiting
# There should be FOUR IPsec SA states (two sets), all with same
# reqid. And there should be one set of tunnel policies using the
# configured ipsec_spd_t label, and no outgoing %trap policy
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
# The IKE SA should be associated with the template connection
ipsec showstates | sed -e 's/=[1-9][0-9]*B/=<NNN>B/g'
