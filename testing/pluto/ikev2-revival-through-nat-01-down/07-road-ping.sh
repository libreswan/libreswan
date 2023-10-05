# confirm the revival
../../guestbin/wait-for.sh --match '#4: responder established Child SA using #3' -- cat /tmp/pluto.log
ipsec traffic
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec traffic
