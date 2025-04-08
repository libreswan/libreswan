# should be the trap
ipsec _kernel policy

# west gets an acquire; negotiates up to IKE_AUTH

../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for-pluto.sh 'initiate on-demand for packet'
../../guestbin/wait-for-pluto.sh '#1: sent IKE_SA_INIT request'

../../guestbin/drip-inbound.sh 1 '#1: processed IKE_SA_INIT response'
../../guestbin/wait-for-pluto.sh '#1: sent IKE_AUTH request'
../../guestbin/wait-for-inbound.sh 2

# should be the block
ipsec _kernel policy
