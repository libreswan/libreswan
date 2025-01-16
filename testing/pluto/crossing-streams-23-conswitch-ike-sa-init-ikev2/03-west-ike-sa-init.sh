# Initiate "a" with all packets blocked.
#
# This will create the negotiating IKE SA #1, and then hang.

ipsec whack --impair block_outbound:yes
ipsec up a --asynchronous
../../guestbin/wait-for-pluto.sh --match '"a" #1: IMPAIR: blocking outbound message 1'
../../guestbin/wait-for-pluto.sh --match '"a" #1: sent IKE_SA_INIT request'

# With connection "a"'s IKE SA #1 stuck, unblock so that the peer's
# IKE SA #2, which will cross "a", can establish

ipsec whack --impair block_outbound:no
