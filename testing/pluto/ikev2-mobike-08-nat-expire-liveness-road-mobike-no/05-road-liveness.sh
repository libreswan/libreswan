../../guestbin/wait-for-pluto.sh --match '10 second timeout exceeded'
../../guestbin/wait-for-pluto.sh --match '#4: initiator established Child SA using #3'
../../guestbin/ping-once.sh --up -I 100.64.0.1 192.0.2.254
ipsec trafficstatus
