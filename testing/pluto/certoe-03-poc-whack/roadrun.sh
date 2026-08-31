#secret sauce whack vs packet triggred.
ipsec whack --oppohere 192.1.3.209 --oppothere 192.1.2.23

../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_SA_INIT request'
../../guestbin/wait-for-pluto.sh --match '#1: sent IKE_AUTH request'
../../guestbin/wait-for-pluto.sh --match '#1: initiator established IKE SA'
../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA using #1'

# wait on OE retransmits and rekeying
sleep 5

# should show established tunnel and no bare shunts
ipsec trafficstatus
ipsec shuntstatus
ipsec _kernel state
ipsec _kernel policy

# ping should succeed through tunnel
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
echo done
