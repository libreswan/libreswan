# OE has been triggered.
# there should be no %pass shunts on either side and an active tunnel
ipsec trafficstatus
ipsec shuntstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
