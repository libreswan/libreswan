# OE has been triggered.
# there should be no %pass shunts on either side and an active tunnel and no partial states
ipsec status |grep STATE_
ipsec trafficstatus
ipsec shuntstatus
../../pluto/bin/ipsec-look.sh
