# wait for EAST's delete message to be blocked

../../guestbin/wait-for-inbound.sh 1

# stop further blocking so revival can occur

ipsec whack --no-impair block_inbound
ipsec whack --no-impair block_outbound

# Process EAST's delete Child SA request

../../guestbin/drip-inbound.sh 1 '#2: connection is supposed to remain up'
../../guestbin/wait-for-pluto.sh '#2: ESP traffic information'

# revived

../../guestbin/wait-for-pluto.sh '#4: initiator established Child SA using #3'
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec trafficstatus
