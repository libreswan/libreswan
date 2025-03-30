# We should already have a %trap policy because we have a
# 192.1.2.23/32 group-instance
ipsec _kernel policy 192.1.2.23

# Trigger a private-or-clear.  Since the peer is down will fail after
# several IKE_SA_INIT retransmits.

../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23

# Wait for the first retransmit and then check that policy et.al. are
# correct.  At this point, since the connection owns the kernel
# policy, there are no bare shunts.

../../guestbin/wait-for-pluto.sh '^".*#1: .*retransmission; will wait 0.5 seconds'
ipsec _kernel policy 192.1.2.23
ipsec whack --shuntstatus
ipsec showstates

# Since there's already an IKE_SA in-flight, pings at this point
# should be ignored.

../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
ipsec showstates

# Now wait for the fatal timeout.  This triggers the deletion of both
# the state and the template connection, and the kernel policy will be
# owned by a bare shunt.

../../guestbin/wait-for-pluto.sh '^".*#1:.* 5 second timeout exceeded'
ipsec _kernel policy 192.1.2.23
ipsec whack --shuntstatus
ipsec showstates

# Since there's a bare shunt ignoring things, pings at this point
# should be ignored and no new states should be created.

../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
ipsec showstates

# Now wait for the bare shunt to expire.

../../guestbin/wait-for.sh --no-match oe-failing -- ipsec whack --shuntstatus
ipsec _kernel policy 192.1.2.23
ipsec whack --shuntstatus
ipsec showstates

# Since the bare shunt as gone, a ping should start a new IKE SA.

../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for-pluto.sh '^".*#2: .*retransmission; will wait 0.5 seconds'
