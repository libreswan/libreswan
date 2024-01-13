# wait for first tunnel (#2) to establish
../../guestbin/wait-for-pluto.sh '^".*#2 established Child SA'
../../guestbin/ping-once.sh --up 192.0.2.254

# second tunnel (#3) piggybacks on #1 after #2 establishes
# it seems the ping goes all alien
../../guestbin/wait-for-pluto.sh '^".*#3 established Child SA'
../../guestbin/ping-once.sh --up 192.0.20.254
