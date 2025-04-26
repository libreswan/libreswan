# trigger TCP
../../guestbin/ping-once.sh --fire-and-forget -I 192.1.2.45 192.1.2.23
../../guestbin/wait-for-pluto.sh --match '#2: initiator established Child SA'

../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec trafficstatus
ipsec _kernel state
ipsec _kernel policy
