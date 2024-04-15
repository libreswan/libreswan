# wait for EAST's delete message to be blocked

../../guestbin/wait-for-inbound.sh 1

# stop further blocking so revival can occur

ipsec whack --no-impair block_inbound
ipsec whack --no-impair block_outbound

# Process EAST's delete IKE SA request
#
# It will delete WEST's IKE SA making the outstanding delete Child SA
# request pointless.

../../guestbin/drip-inbound.sh 1 '#2: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh '#2: ESP traffic information'
../../guestbin/wait-for-pluto.sh '#1: deleting IKE SA'

# revived

../../guestbin/wait-for-pluto.sh '#4: initiator established Child SA using #3'
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
