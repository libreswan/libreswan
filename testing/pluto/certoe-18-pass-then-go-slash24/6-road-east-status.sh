# OE has been triggered.
# there should be no %pass shunts on either side and an active tunnel and no partial states
ipsec showstates
ipsec trafficstatus
ipsec shuntstatus
ipsec _kernel state
ipsec _kernel policy
