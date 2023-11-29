# we can transmit in the clear
../../guestbin/ping-once.sh --up 192.1.2.23
# bring up the tunnel
ipsec auto --up SAwest-east
# use the tunnel
../../guestbin/ping-once.sh --up 192.1.2.23
# show the tunnel!
ipsec whack --trafficstatus
# "Time to shut down my computer!"...
ipsec whack --shutdown
# ...but unless the delete SA is acknowledged, this ping will fail,
# as our peer still routed us
sleep 5
../../guestbin/ping-once.sh --up 192.1.2.23
echo done
