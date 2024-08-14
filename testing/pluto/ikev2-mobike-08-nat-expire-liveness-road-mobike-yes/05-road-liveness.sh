../../guestbin/wait-for-pluto.sh --match 'sending .* liveness probe'
../../guestbin/ping-once.sh --up -I 100.64.0.1 192.0.2.254
ipsec trafficstatus
