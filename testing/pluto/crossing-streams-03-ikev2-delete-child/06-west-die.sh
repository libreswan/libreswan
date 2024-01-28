# wait for EAST's delete message to be blocked
../../guestbin/wait-for-pluto.sh 'IMPAIR: blocking inbound message 1'

# stop further blocking so revival can occure
ipsec whack --no-impair block_inbound
ipsec whack --no-impair block_outbound

# Process EAST's delete request before letting WEST's request go out.
#
# For a Child SA delete, because WEST has a delete in flight, it will
# respond with an empty notify where as normally it would respond with
# inbound SPIs.
../../guestbin/drip-inbound.sh 1 '#2: ESP traffic information'

# Let WEST's delete message to EAST go out. Since EAST has completed
# it's delete exchange it should respond with an empty notify instead
# of outbound SPIs as they have been deleted.
ipsec whack --impair drip_outbound:1

# revived
../../guestbin/wait-for-pluto.sh '#3: initiator established Child SA using #1'
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
