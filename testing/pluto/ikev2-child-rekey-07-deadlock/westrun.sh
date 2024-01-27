# IKE: #1 CHILD: #2, #3, #4, and #5
ipsec auto --up west-east

# CHILD #2->#6
ipsec whack --rekey-child --name west-east/1x0 --async

# CHILD #3->#7
ipsec whack --rekey-child --name west-east/2x0 --async

# CHILD #4->#8
ipsec whack --rekey-child --name west-east/3x0 --async

# CHILD #5->#9
ipsec whack --rekey-child --name west-east/4x0 --async

# state #1 in STATE_V2_ESTABLISHED_IKE_SA, and #6, #7, #8 and #9 in
# STATE_V2_ESTABLISHED_CHILD_SA anything other state is a sign of
# regression
../../guestbin/wait-for.sh --match '#6:' -- ipsec trafficstatus
../../guestbin/wait-for.sh --match '#7:' -- ipsec trafficstatus
../../guestbin/wait-for.sh --match '#8:' -- ipsec trafficstatus
../../guestbin/wait-for.sh --match '#9:' -- ipsec trafficstatus

../../guestbin/wait-for.sh --no-match '#5:' -- ipsec trafficstatus

