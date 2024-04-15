# wait for EAST's delete message to be blocked

../../guestbin/wait-for-inbound.sh 1

# stop further blocking so revival can occur

ipsec whack --no-impair block_inbound
ipsec whack --no-impair block_outbound

# Process EAST's delete Child SA request.
#
# For a Child SA delete, because WEST has a delete in flight, it will
# respond with an empty notify where as normally it would respond with
# inbound SPIs.

../../guestbin/drip-inbound.sh 1 '#2: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh '#2: ESP traffic information'

# Now release WEST's delete Child SA request which is blocking WEST's
# attempt to revive the connection deleted above.  Since the Child
# SA's already deleted the response is ignored.

../../guestbin/drip-outbound.sh 1 '#1: Child SA #2 no longer exists'

# revived

../../guestbin/wait-for-pluto.sh '#3: initiator established Child SA using #1'
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
