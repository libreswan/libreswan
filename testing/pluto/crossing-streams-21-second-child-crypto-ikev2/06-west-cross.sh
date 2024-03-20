# Process the response to this end's CREATE_CHILD_SA request.  It
# needs to finish DH so expect it it be submitted to the crypto
# helper.

../../guestbin/drip-inbound.sh 1 '#3: IMPAIR: job 4 helper 0 #1/#3 .* pausing for 5 seconds'

# Now process the peer's CREATE_CHILD_SA request.  This two needs a
# full crypto calculation so expect it to be sent to the crypto
# helper.
#
# XXX: it is tied to #1/#1 but should be #1/#4

../../guestbin/drip-inbound.sh 2 '#4: IMPAIR: job 5 helper 0 #1/#4 .* pausing for 5 seconds'

# finally wait for things to establish
../../guestbin/wait-for-pluto.sh '#4: responder established Child SA using #1'
../../guestbin/wait-for-pluto.sh '#3: initiator established Child SA using #1'

ipsec whack --no-impair block_inbound
ipsec whack --no-impair helper_thread_delay
