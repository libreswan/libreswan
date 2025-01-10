# confirm the revival
../../guestbin/wait-for-pluto.sh '^".*#4: responder established Child SA using #3'
ipsec traffic
../../guestbin/ping-once.sh --up 192.0.2.254
ipsec traffic
