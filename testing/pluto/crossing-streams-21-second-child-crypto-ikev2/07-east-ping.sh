# Ping from east, but first make certain that the tunnels are up
../../guestbin/wait-for-pluto.sh '#4: initiator established Child SA using #1'

../../guestbin/ping-once.sh --up -I 192.0.20.254 192.0.3.254
