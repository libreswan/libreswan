ipsec up --asynchronous west-to-east

# step through the main mode exchange

../../guestbin/wait-for.sh --match '#1: sent Main Mode request' -- cat /tmp/pluto.log

../../guestbin/drip-inbound.sh 1 '#1: sent Main Mode I2'

../../guestbin/drip-inbound.sh 2 '#1: sent Main Mode I3'

../../guestbin/drip-inbound.sh 3 '#1: ISAKMP SA established'

# wait for quick mode response
../../guestbin/wait-for.sh --match '#2: sent Quick Mode request' -- cat /tmp/pluto.log
../../guestbin/wait-for-inbound.sh 4
