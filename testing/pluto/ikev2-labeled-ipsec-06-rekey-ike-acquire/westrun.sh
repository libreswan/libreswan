# Establish a childless IKE SA which will install the policy ready for
# an acquire.
ipsec auto --up labeled
ipsec _kernel state
ipsec _kernel policy

# Initiate a rekey of the IKE SA but drop the initial CREATE_CHILD_SA
# request.  This will cause the exchange to become stuck; the
# retransmit, scheduled for 10s, will unstick it.
ipsec whack --impair drop_outbound:1
ipsec whack --rekey-ike --asynchronous --name labeled
../../guestbin/wait-for.sh --match REKEY_IKE_I1 -- ipsec whack --showstates

# Trigger traffic using the predefined ping_t context.  Because the
# rekey SA is stuck it will start on the old #1 IKE SA's queue and
# then migrated to the new SA queue when things resume.
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec trafficstatus
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --up     -I 192.1.2.45 192.1.2.23

# there should be 1 tunnel in each direction
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state

echo done
