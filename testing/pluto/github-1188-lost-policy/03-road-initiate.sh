ipsec start
../../guestbin/wait-until-pluto-started
# give OE policies time to load
../../guestbin/wait-for.sh --match 'loaded 2,' -- ipsec auto --status

# fail to send send IKE_SA_INIT
ipsec whack --impair suppress_retransmits
../../guestbin/ping-once.sh --down -I 192.1.3.209 192.1.2.23

# OE send message is suppressed; this is next best
../../guestbin/wait-for-pluto.sh 'initiator sent IKE_SA_INIT request'

# dump state/policy for larval OE connection
ipsec showstates
ipsec _kernel policy
