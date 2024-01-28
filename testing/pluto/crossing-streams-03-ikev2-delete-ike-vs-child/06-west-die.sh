# wait for EAST's delete message to be blocked
../../guestbin/wait-for-pluto.sh 'IMPAIR: blocking inbound message 1'

# stop further blocking so revival can occure
ipsec whack --no-impair block_inbound
ipsec whack --no-impair block_outbound

# Let WEST's delete message to EAST go out (pointless though).
ipsec whack --impair drip_outbound:1

# Process EAST's delete IKE SA request before letting WEST's request
# go out.  It will delete WEST's IKE SA making the outstanding delete
# Child SA pointless.
../../guestbin/drip-inbound.sh 1 '#2: ESP traffic information'

# revived
../../guestbin/wait-for-pluto.sh '#4: initiator established Child SA using #3'
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
