ipsec up --asynchronous west-to-east

# step through the main mode exchange

../../guestbin/wait-for-pluto.sh '#1: sent Main Mode request'

../../guestbin/drip-inbound.sh 1 '#1: sent Main Mode I2'

../../guestbin/drip-inbound.sh 2 '#1: sent Main Mode I3'

../../guestbin/drip-inbound.sh 3 '#1: ISAKMP SA established'

# wait for quick mode response
../../guestbin/wait-for-pluto.sh '#2: sent Quick Mode request'
../../guestbin/wait-for-inbound.sh 4
