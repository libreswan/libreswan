# use the tunnel
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# show the tunnel
ipsec whack --trafficstatus
# Let R_U_THERE packets flow
sleep 10
sleep 10
