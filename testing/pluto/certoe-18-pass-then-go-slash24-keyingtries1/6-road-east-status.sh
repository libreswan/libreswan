# OE has been triggered.
# there should be no %pass shunts on either side and an active tunnel and no partial IKE states
ipsec status |grep STATE_
ipsec trafficstatus
ipsec shuntstatus
../../guestbin/ipsec-look.sh
