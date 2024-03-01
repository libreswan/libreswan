# should be the trap
../../guestbin/ipsec-kernel-policy.sh

# west gets an acquire; negotiates up to IKE_AUTH

../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
../../guestbin/wait-for-pluto.sh 'initiate on-demand for packet'
../../guestbin/wait-for-pluto.sh '#1: sent IKE_SA_INIT request'
../../guestbin/wait-for-inbound.sh 1

# should be the block
../../guestbin/ipsec-kernel-policy.sh
