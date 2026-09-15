# trigger ping, this will be lost
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_SA_INIT request'
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_AUTH request'
../../guestbin/wait-for-pluto.sh --match '#1: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA using #1'

# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23

# get assigned 10.0.10.1 so expect:
#    tunnel: 10.0.10.1/32<->192.1.2.23/32
#    CAT: 192.1.3.209/32->192.1.2.23/32
#    TRAP: 192.1.3.209/32->192.1.2.23/24
ipsec _kernel policy
ipsec _kernel state
ipsec trafficstatus
ipsec shuntstatus
