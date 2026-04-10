# use the tunnel
../../guestbin/ping-once.sh --up 192.1.2.23
# show the tunnel!
ipsec trafficstatus

# "Time to shut down my computer!"...
ipsec stop

# ...but unless the delete SA is acknowledged, this ping will fail, as
# our peer still routed us
../../guestbin/ping-once.sh --up 192.1.2.23
echo done
