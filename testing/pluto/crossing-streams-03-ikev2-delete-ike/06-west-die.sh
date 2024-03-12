# wait for EAST's delete message to be blocked
../../guestbin/wait-for-pluto.sh 'IMPAIR: blocking inbound message 1'

# stop further blocking so revival can occur
ipsec whack --no-impair block_inbound
ipsec whack --no-impair block_outbound

# Process EAST's delete request before letting WEST's request go out.
ipsec whack --impair drip_inbound:1

# Let WEST's delete message to EAST go out.  Since EAST has completed
# it's delete exchange, IKE is gone.
ipsec whack --impair drip_outbound:1

# revived
../../guestbin/wait-for-pluto.sh --timeout 80 '#4: initiator established Child SA using #3'
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
