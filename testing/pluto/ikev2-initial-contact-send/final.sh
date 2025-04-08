ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
# one INITIAL_CONTACT payload is sent, in the single IKE_AUTH
# on east, shows up twice in log for a single payload
# on west, shows up once in log for a single payload
grep INITIAL /tmp/pluto.log
