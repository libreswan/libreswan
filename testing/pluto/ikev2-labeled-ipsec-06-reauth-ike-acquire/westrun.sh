# Establish a childless IKE SA which will install the policy ready for
# an acquire.
ipsec auto --up labeled
ipsec _kernel state
ipsec _kernel policy

../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for.sh --match 192.1.2.23 -- ipsec trafficstatus
../../guestbin/ping-once.sh --runcon "system_u:system_r:ping_t:s0:c1.c256" --up     -I 192.1.2.45 192.1.2.23

# Initiate a replace of state #1; the next outgoing message which will
# be a IKE_SA_INIT for the replacemnt.
ipsec whack --impair drop_outbound:1
ipsec whack --asynchronous --impair trigger_v2_reauth:1
../../guestbin/wait-for.sh --match PARENT_I1 -- ipsec whack --showstates

# let another on-demand label establish
echo "quit" | runcon -u system_u -r system_r -t sshd_t nc -w 50 192.1.2.23 22 2>&1 | sed "s/received in .*$/received .../"

# there should be 1 tunnel in each direction
ipsec trafficstatus
# there should be no bare shunts
ipsec shuntstatus
# let larval state expire
../../guestbin/wait-for.sh --no-match ' spi 0x00000000 ' -- ipsec _kernel state

echo done
